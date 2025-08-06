namespace SatCredentialsCore;

using System.Security.Cryptography;

public interface ISatCredentials
{
    SatCredentialsConstants.CertificateType TipoCertificado { get; }

    string Subject { get; }

    string Issuer { get; }

    SatCredentialsConstants.TaxpayerType TipoPersona { get; }

    string RazonSocial { get; }

    string Rfc { get; }

    string RfcRepresentanteLegal { get; }

    string Curp { get; }

    string CurpRepresentanteLegal { get; }

    string NombreSucursal { get; }

    string Email { get; }

    string SerialNumber { get; }

    int Version { get; }

    DateTime ValidFrom { get; }

    DateTime ValidTo { get; }

    bool IsInForce { get; }

    RSA? PublicKey { get; }
    
    RSA? PrivateKey { get; }

    byte[] PublicKeyBytes { get; }

    string PublicKeyString { get; }

    string? PublicKeyPem { get; }

    string? RSAPublicKeyPem { get; }

    string CertificatePem { get; }

    byte[] Pfx { get; }

    byte[] PublicKeyBytesFromPrivateKey { get; }

    string PublicKeyPemFromPrivateKey { get; }

    byte[] PrivateKeyBytes { get; }

    string RSAPrivateKeyPem { get; }

    string Pkcs8PrivateKeyPem { get; }

    string CertificateB64 { get; }

    byte[] Encrypt(byte[] data);

    byte[] Decrypt(byte[] data);

    byte[] SingSHA256(byte[] data);

    byte[] SingSHA1(byte[] data);

    bool VerifySHA256(byte[] data, byte[] signature);

    bool VerifySHA1(byte[] data, byte[] signature);
}
