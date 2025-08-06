using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SatCredentialsCore;

public class SatCredentials : ISatCredentials, IDisposable
{
    private readonly char[] _privateKeyPassword;
    private readonly X509Certificate2 _certificate;
    private readonly RSA _privateKey;
    private readonly RSA _publicKey;

    public SatCredentials(byte[] certificateBytes, byte[] privateKeyBytes, string privateKeyPassword)
    {
        this._privateKeyPassword = privateKeyPassword.ToCharArray();
        try
        {
#if NET9_0_OR_GREATER
        // Disponible solo en .NET 8+
        _certificate = X509CertificateLoader.LoadCertificate(certificateBytes);
#else
            // Compatible con .NET 6 y .NET 7
            _certificate = new X509Certificate2(certificateBytes);
#endif
        }
        catch (CryptographicException ex)
        {
            throw new SatCredentialsError("Error reading Certificate.", ex);
        }
        
        this._publicKey = this._certificate.GetRSAPublicKey() ?? throw new SatCredentialsError("Error loading Sat Certificate. Certificate does not2 have Public Key.");
        
        try
        {
            this._privateKey = RSA.Create();
            this._privateKey.ImportEncryptedPkcs8PrivateKey(this._privateKeyPassword, privateKeyBytes, out _);
        }
        catch (CryptographicException ex)
        {
            throw new SatCredentialsError("Error reading Private Key, the password may be incorrect.", ex);
        }
        
        var publicKeyParameters = this._publicKey.ExportParameters(false);
        var privateKeyParameters = _privateKey.ExportParameters(true);

        // Validates if Certificate belongs Private Key.
        var cerBelongsKey = false;
        if (publicKeyParameters.Modulus is not null 
            && publicKeyParameters.Exponent is not null 
            && privateKeyParameters.Modulus is not null 
            && privateKeyParameters.Exponent is not null)
        {
            cerBelongsKey = publicKeyParameters.Modulus.SequenceEqual(privateKeyParameters.Modulus) &&
                publicKeyParameters.Exponent.SequenceEqual(privateKeyParameters.Exponent);
        }
        
        if (!cerBelongsKey)
            throw new SatCredentialsError("Error loading Sat Certificate. Certificate doesn't match Private Key.");

        // Validates if certificate is in force.
        if (!this.IsInForce)
            throw new SatCredentialsError("The certificate is expired. It is not valid in current dates.");

        // Validates that SAT is the certificate issuer.
        if (!_certificate.Issuer.Contains("servicio de administracion tributaria", StringComparison.OrdinalIgnoreCase))
            throw new SatCredentialsError("The certificate is not emitted by SAT.");
    }


    public SatCredentials(string certificateFilename, string privateKeyFilename, string privateKeyPassword)
     : this(File.ReadAllBytes(certificateFilename), File.ReadAllBytes(privateKeyFilename), privateKeyPassword)
    {}

    public List<KeyValuePair<string, string>> SubjectKeyValuePairs 
    {
        get {
            return _certificate.Subject.Split(',').Select(
                x => new KeyValuePair<string, string>(x.Split('=')[0].Trim(), x.Split('=')[1].Trim())
            ).ToList();
        }
    }

    public List<KeyValuePair<string, string>> IssuerKeyValuePairs {
        get
        {
            return _certificate.Issuer.Split(',').Select(
                x => new KeyValuePair<string, string>(x.Split('=')[0].Trim(), x.Split('=')[1].Trim())
            ).ToList();
        }
    }

    public string Rfc {
        get {
            var rfcs = SubjectKeyValuePairs.FirstOrDefault(
                x => x.Key.Equals("OID.2.5.4.45") || x.Key.Equals("x500UniqueIdentifier")
            ).Value;
            var rfcsList = rfcs.Split('/').Select(x=> x.Trim()).ToList();
            return rfcsList[0];
        }
    }
    
    public string RfcRepresentanteLegal {
        get {
            var rfcs = SubjectKeyValuePairs.FirstOrDefault(
                x => x.Key.Equals("OID.2.5.4.45") || x.Key.Equals("x500UniqueIdentifier")
            ).Value;
            var rfcList = rfcs.Split('/').Select(x=> x.Trim()).ToList();
            return rfcList.Count == 2 ? rfcList[1] : string.Empty;
        }
    }

    public string Curp {
        get {
            var curps = SubjectKeyValuePairs.FirstOrDefault(x => x.Key.Equals("SERIALNUMBER")).Value.Replace("\"", "");
            var curpList = curps.Split('/').Select(x=> x.Trim()).ToList();
            return !string.IsNullOrEmpty(curpList[0]) ? curpList[0] : string.Empty;
        }
    }

    public string CurpRepresentanteLegal {
        get {
            var curps = SubjectKeyValuePairs.FirstOrDefault(x => x.Key.Equals("SERIALNUMBER")).Value.Replace("\"", "");
            var curpsList = curps.Split('/').Select(x=> x.Trim()).ToList();
            return curpsList.Count == 2 ? curpsList[1] : string.Empty;
        }
    }

    public SatCredentialsConstants.TaxpayerType TipoPersona => Rfc.Length == 12 ? SatCredentialsConstants.TaxpayerType.MORAL : SatCredentialsConstants.TaxpayerType.FISICA;

    public string Email  => SubjectKeyValuePairs.FirstOrDefault(x => x.Key.Equals("E")).Value ?? string.Empty;

    public string RazonSocial {
        get {
            var legalName = SubjectKeyValuePairs.FirstOrDefault(x => x.Key.Equals("O")).Value;
            if (string.IsNullOrEmpty(legalName) || this.TipoPersona != SatCredentialsConstants.TaxpayerType.MORAL)
                return legalName;
            
            var regSoc = SatCredentialsConstants.RegimenesSocietarios.FirstOrDefault(x => legalName.EndsWith(x.Key));
            if (regSoc.Key is not null)
                legalName = legalName[..^(regSoc.Key.Length + 1)];
            
            return legalName;
        }
    }

    public string NombreSucursal => SubjectKeyValuePairs.FirstOrDefault(x => x.Key.Equals("OU")).Value ?? string.Empty;

    public string SerialNumber => Encoding.ASCII.GetString(this._certificate.GetSerialNumber().Reverse().ToArray());

    //public SatCredentialsConstants.CertificateType TipoCertificado => this._certificate.Extensions.Count == 4 ? SatCredentialsConstants.CertificateType.FIEL : SatCredentialsConstants.CertificateType.CSD;

    public SatCredentialsConstants.CertificateType TipoCertificado
    {
        get
        {
            var ou = this.SubjectKeyValuePairs.FirstOrDefault(x => x.Key.Equals("OU")).Value;
            return !string.IsNullOrEmpty(ou) ? SatCredentialsConstants.CertificateType.CSD : SatCredentialsConstants.CertificateType.FIEL;
        }
    }

    public string CertificateB64 => Convert.ToBase64String(this._certificate.GetRawCertData());

    public bool IsInForce {
        get {

            var validFromUtc = this._certificate.NotBefore.ToUniversalTime();
            var validToUtc = this._certificate.NotAfter.ToUniversalTime();
            var now = DateTime.UtcNow;
            return now >= validFromUtc && now <= validToUtc;
        }
    }

    public virtual RSA PublicKey => this._publicKey;

    public virtual RSA PrivateKey => this._privateKey;

    public virtual string Subject => this._certificate.Subject;

    public virtual string Issuer => this._certificate.Issuer;

    public virtual byte[] Pfx => this._certificate.Export(X509ContentType.Pfx, this._privateKeyPassword.ToString());
    
    public virtual int Version => this._certificate.Version;

    public virtual DateTime ValidFrom => this._certificate.NotBefore.ToUniversalTime();

    public virtual DateTime ValidTo => this._certificate.NotAfter.ToUniversalTime();

    public virtual byte[] PublicKeyBytes => this._certificate.GetPublicKey();

    public virtual string PublicKeyString => this._certificate.GetPublicKeyString();

    public virtual string PublicKeyPem => PublicKey.ExportSubjectPublicKeyInfoPem();

    public virtual string RSAPublicKeyPem => PublicKey.ExportRSAPublicKeyPem();

    public virtual string CertificatePem => _certificate.ExportCertificatePem();

    public virtual byte[] PublicKeyBytesFromPrivateKey => this._privateKey.ExportRSAPublicKey();

    public virtual string PublicKeyPemFromPrivateKey => PrivateKey.ExportSubjectPublicKeyInfoPem();
    
    public virtual byte[] PrivateKeyBytes => this._privateKey.ExportRSAPrivateKey();

    public virtual string RSAPrivateKeyPem => PrivateKey.ExportRSAPrivateKeyPem();


    public virtual string Pkcs8PrivateKeyPem => PrivateKey.ExportPkcs8PrivateKeyPem();

    public virtual byte[] Encrypt(byte[] data) => this.PublicKey.Encrypt(data, RSAEncryptionPadding.Pkcs1);

    public virtual byte[] Decrypt(byte[] data) => this._privateKey.Decrypt(data, RSAEncryptionPadding.Pkcs1);

    public virtual byte[] SingSHA1(byte[] data) => this._privateKey.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

    public virtual byte[] SingSHA256(byte[] data) => this._privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    public virtual bool VerifySHA1(byte[] data, byte[] signature) => this.PublicKey.VerifyData(data, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

    public virtual bool VerifySHA256(byte[] data, byte[] signature) => this.PublicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

    public void Dispose()
    {
        _privateKey?.Dispose();
        _publicKey?.Dispose();
        _certificate?.Dispose();
    }
}
