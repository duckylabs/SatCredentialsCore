using SatCredentialsCore;
using System.Security.Cryptography;
using System.Text;
using Moq;
using SatCredentialsCoreTests.TestData;

namespace SatCredentialsCoreTests;

public class TestCredentials
{
    #region Constructor Tests

    [Theory]
    [ClassData(typeof(ValidSATFilesTestData))]
    public void SatCredentials_CreateFromFilenames_ShouldInitializeProperties(string certFilename, string keyFilename, string keyPassword)
    {
        // Arrange & Act
        var credentials = new SatCredentials(
            TestUtils.GetTestFilePath(certFilename),
            TestUtils.GetTestFilePath(keyFilename),
            keyPassword
        );
        
        // Assert
        Assert.NotNull(credentials.Rfc);
        Assert.NotEmpty(credentials.Rfc);
        Assert.NotNull(credentials.RazonSocial);
        Assert.NotEmpty(credentials.RazonSocial);
        Assert.NotNull(credentials.Curp);
        Assert.NotEmpty(credentials.Curp);
        Assert.NotNull(credentials.Issuer);
        Assert.NotEmpty(credentials.Issuer);
        Assert.NotNull(credentials.SerialNumber);
        Assert.NotEmpty(credentials.SerialNumber);
        Assert.NotNull(credentials.SubjectKeyValuePairs);
        Assert.NotEmpty(credentials.SubjectKeyValuePairs);
        Assert.NotNull(credentials.IssuerKeyValuePairs);
        Assert.NotEmpty(credentials.IssuerKeyValuePairs);
        Assert.NotEmpty(credentials.Subject);
        Assert.NotEmpty(credentials.RSAPublicKeyPem);
        Assert.NotEmpty(credentials.RSAPrivateKeyPem);
        Assert.NotEmpty(credentials.PublicKeyString);
        Assert.NotEmpty(credentials.PublicKeyBytes);
        Assert.NotEmpty(credentials.CertificatePem);
        Assert.NotEmpty(credentials.CertificateB64);
        Assert.NotEmpty(credentials.PublicKeyPem);
    }

    [Theory]
    [ClassData(typeof(ValidSATFilesTestData))]
    public void SatCredentials_CreateFromBytes_ShouldReturnValidPfx(string certFilename, string keyFilename, string keyPassword)
    {
        // Arrange
        var certBytes = File.ReadAllBytes(TestUtils.GetTestFilePath(certFilename));
        var keyBytes = File.ReadAllBytes(TestUtils.GetTestFilePath(keyFilename));

        // Act
        var credentials = new SatCredentials(certBytes, keyBytes, keyPassword);
        var pfx = credentials.Pfx;
        File.WriteAllBytes("test.pfx", pfx);

        // Assert
        Assert.NotNull(pfx);
    }

    [Fact]
    public void SatCredentials_CreateWithInvalidCertificateBytes_ShouldThrowSatCredentialsError()
    {
        // Arrange
        var certBytes = new byte[] { 0x01, 0x02, 0x03, 0x04 };
        var keyBytes = new byte[] { 0x05, 0x06, 0x07, 0x08 };
        const string keyPassword = "123456";

        // Act
        var exception = Assert.Throws<SatCredentialsError>(() => new SatCredentials(certBytes, keyBytes, keyPassword));

        // Assert
        Assert.Equal("Error reading Certificate.", exception.Message);
        Assert.IsAssignableFrom<CryptographicException>(exception.InnerException);
    }
    
    [Fact]
    public void SatCredentials_CreateWithNonInForceCertificate_ShouldThrowSatCredentialsError()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8_caduco.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8_caduco.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);

        // Act
        var exception = Assert.Throws<SatCredentialsError>(() => new SatCredentials(certBytes, keyBytes, keyPassword));

        // Assert
        Assert.Equal("The certificate is expired. It is not valid in current dates.", exception.Message);
    }
    
    [Fact]
    public void SatCredentials_CreateWithNonSatCert_ShouldThrowSatCredentialsError()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/non_sat_csd.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/non_sat_csd.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);

        // Act
        var exception = Assert.Throws<SatCredentialsError>(() => new SatCredentials(certBytes, keyBytes, keyPassword));

        // Assert
        Assert.Equal("The certificate is not emitted by SAT.", exception.Message);
    }

    [Fact]
    public void SatCredentials_CreateWithMismatchedKeyAndCert_ShouldThrowSatCredentialsError()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/EKU9003173C9/csd_EKU9003173C9.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);

        // Act
        var ex = Record.Exception(() => new SatCredentials(certBytes, keyBytes, keyPassword));

        // Assert
        Assert.IsType<SatCredentialsError>(ex);
        Assert.Equal("Error loading Sat Certificate. Certificate doesn't match Private Key.", ex.Message);
    }

    [Fact]
    public void SatCredentials_CreateWithWrongPassword_ShouldThrowSatCredentialsError()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key");
        const string keyPassword = "wrong password";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);

        // Act
        var ex = Record.Exception(() => new SatCredentials(certBytes, keyBytes, keyPassword));

        // Assert
        Assert.IsType<SatCredentialsError>(ex);
        Assert.Equal("Error reading Private Key, the password may be incorrect.", ex.Message);
    }

    [Fact]
    public void SatCredentials_CreateWithInexistentCertificate_ShouldThrowFileNotFoundException()
    {
        // Arrange
        var invalidCertFilename = TestUtils.GetTestFilePath("Resources/certs/CACX7605101P8/InvalidFileName.cer");
        var keyFilename = TestUtils.GetTestFilePath("Resources/certs/CACX7605101P8/csd_CACX7605101P8.key");

        // Act
        var ex = Record.Exception(() => new SatCredentials(invalidCertFilename, keyFilename, ""));

        // Assert
        Assert.IsType<FileNotFoundException>(ex);
        Assert.Equal($"Could not find file '{invalidCertFilename}'.", ex.Message);
    }

    [Fact]
    public void SatCredentials_CreateWithInexistentPrivateKey_ShouldThrowFileNotFoundException()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var invalidKeyFilename = TestUtils.GetTestFilePath("Resources/certs/CACX7605101P8/InvalidFileName.key");

        // Act
        var ex = Record.Exception(() => new SatCredentials(certFilename, invalidKeyFilename, ""));

        // Assert
        Assert.IsType<FileNotFoundException>(ex);
        Assert.Equal($"Could not find file '{invalidKeyFilename}'.", ex.Message);
    }
    
    [Fact]
    public void Dispose_ShouldNotThrowException()
    {
        // Arrange
        var certBytes = File.ReadAllBytes(TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer"));
        var keyBytes = File.ReadAllBytes(TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key"));
        const string keyPassword = "12345678a";

        var credentials = new SatCredentials(certBytes, keyBytes, keyPassword);

        // Act
        var ex = Record.Exception(() => credentials.Dispose());

        // Assert
        Assert.Null(ex);
    }

    #endregion

    #region Certificate Data Tests

    [Theory]
    [ClassData(typeof(ValidCertificatesTestData))]
    public void SatCredentials_GetCertificateData_ShouldMatchExpectedValues(
        string certFilename,
        string keyFilename,
        string keyPassword,
        SatCredentialsConstants.CertificateType certType,
        SatCredentialsConstants.TaxpayerType taxpayerType,
        string email,
        string rfc,
        string rfcRepresentante,
        string curp,
        string curpRepresentante,
        string razonSocial,
        string serialNumber,
        bool isValid,
        string nombreSucursal
    )
    {
        // Arrange
        var credentials = new SatCredentials(
            TestUtils.GetTestFilePath(certFilename),
            TestUtils.GetTestFilePath(keyFilename),
            keyPassword
        );

        // Act & Assert
        Assert.Equal(certType, credentials.TipoCertificado);
        Assert.Equal(taxpayerType, credentials.TipoPersona);
        Assert.Equal(email, credentials.Email);
        Assert.Equal(rfc, credentials.Rfc);
        Assert.Equal(rfcRepresentante, credentials.RfcRepresentanteLegal);
        Assert.Equal(curp, credentials.Curp);
        Assert.Equal(curpRepresentante, credentials.CurpRepresentanteLegal);
        Assert.Equal(razonSocial, credentials.RazonSocial);
        Assert.Equal(serialNumber, credentials.SerialNumber);
        Assert.Equal(isValid, credentials.IsInForce);
        Assert.Equal(nombreSucursal, credentials.NombreSucursal);
        Assert.IsType<DateTime>(credentials.ValidFrom);
        Assert.IsType<DateTime>(credentials.ValidTo);
        Assert.Equal(3, credentials.Version);
    }

    #endregion

    #region Encryption & Decryption Tests

    [Theory]
    [ClassData(typeof(ValidSATFilesTestData))]
    public void SatCredentials_EncryptAndDecrypt_ShouldReturnOriginalData(string certFilename, string keyFilename, string keyPassword)
    {
        // Arrange
        var credentials = new SatCredentials(
            TestUtils.GetTestFilePath(certFilename),
            TestUtils.GetTestFilePath(keyFilename),
            keyPassword
        );
        var data = Encoding.ASCII.GetBytes("Hello world!");

        // Act
        var encryptedData = credentials.Encrypt(data);
        var decryptedData = credentials.Decrypt(encryptedData);

        // Assert
        Assert.NotEqual(data, encryptedData);
        Assert.Equal(data, decryptedData);
    }

    [Fact]
    public void SatCredentials_DecryptWithInvalidDataSize_ShouldThrowCryptographicException()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);
        var data = Encoding.UTF8.GetBytes("Hello world!");
        var credentials = new SatCredentials(certBytes, keyBytes, keyPassword);

        // Act
        var ex = Record.Exception(() => credentials.Decrypt(data));

        // Assert
        Assert.IsType<CryptographicException>(ex);
        Assert.NotEqual("The length of the data to decrypt is not valid for the size of this key", ex.Message);
    }

    [Fact]
    public void SatCredentials_EncryptDataWithoutPublicKey_ShouldThrowSatCredentialsError()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);
        var data = Encoding.UTF8.GetBytes("Hello world!");

        var mockCredentials = new Mock<SatCredentials>(certBytes, keyBytes, keyPassword);
        mockCredentials.Setup(x => x.Encrypt(It.IsAny<byte[]>())).CallBase();
        mockCredentials.Setup(x => x.PublicKey).Throws(new SatCredentialsError("Certificate does not have a Public Key."));

        // Act
        var ex = Record.Exception(() => mockCredentials.Object.Encrypt(data));

        // Assert
        Assert.IsType<SatCredentialsError>(ex);
        Assert.Equal("Certificate does not have a Public Key.", ex.Message);
    }

    #endregion

    #region Signing Tests

    [Theory]
    [ClassData(typeof(ValidSATFilesTestData))]
    public void SatCredentials_SignAndVerifySHA256_ShouldReturnTrue(string certFilename, string keyFilename, string keyPassword)
    {
        // Arrange
        var credentials = new SatCredentials(
            TestUtils.GetTestFilePath(certFilename),
            TestUtils.GetTestFilePath(keyFilename),
            keyPassword
        );
        var data = Encoding.ASCII.GetBytes("Hello world!");

        // Act
        var signature = credentials.SingSHA256(data);
        var isValid = credentials.VerifySHA256(data, signature);

        // Assert
        Assert.True(isValid);
    }

    [Theory]
    [ClassData(typeof(ValidSATFilesTestData))]
    public void SatCredentials_SignAndVerifySHA1_ShouldReturnTrue(string certFilename, string keyFilename, string keyPassword)
    {
        // Arrange
        var credentials = new SatCredentials(
            TestUtils.GetTestFilePath(certFilename),
            TestUtils.GetTestFilePath(keyFilename),
            keyPassword
        );
        var data = Encoding.ASCII.GetBytes("Hello world!");

        // Act
        var signature = credentials.SingSHA1(data);
        var isValid = credentials.VerifySHA1(data, signature);

        // Assert
        Assert.True(isValid);
    }

    [Fact]
    public void SatCredentials_VerifySHA256WithInvalidSignature_ShouldReturnFalse()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);
        var credentials = new SatCredentials(certBytes, keyBytes, keyPassword);
        var data = Encoding.ASCII.GetBytes("Hello world");

        // Act
        var isValid = credentials.VerifySHA256(data, new byte[] { 123 });

        // Assert
        Assert.False(isValid);
    }

    [Fact]
    public void SatCredentials_VerifySHA256WithoutPublicKey_ShouldThrowSatCredentialsError()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);
        var data = Encoding.ASCII.GetBytes("Hello world");

        var mockCredentials = new Mock<SatCredentials>(certBytes, keyBytes, keyPassword);
        mockCredentials.Setup(x => x.VerifySHA256(It.IsAny<byte[]>(), It.IsAny<byte[]>())).CallBase();
        mockCredentials.Setup(x => x.PublicKey).Throws(new SatCredentialsError("Certificate does not have a Public Key."));

        // Act
        var ex = Record.Exception(() => mockCredentials.Object.VerifySHA256(data, new byte[] { }));

        // Assert
        Assert.IsType<SatCredentialsError>(ex);
        Assert.Equal("Certificate does not have a Public Key.", ex.Message);
    }

    #endregion

    #region Public Key Tests

    [Fact]
    public void SatCredentials_GetPublicKeyPem_ShouldThrowSatCredentialsError_WhenNoPublicKeyAvailable()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);

        var mockCredentials = new Mock<SatCredentials>(certBytes, keyBytes, keyPassword);
        mockCredentials.Setup(x => x.PublicKeyPem).CallBase();
        mockCredentials.Setup(x => x.PublicKey).Throws(new SatCredentialsError("Certificate does not have a Public Key."));

        // Act
        var ex = Record.Exception(() => mockCredentials.Object.PublicKeyPem);

        // Assert
        Assert.IsType<SatCredentialsError>(ex);
        Assert.Equal("Certificate does not have a Public Key.", ex.Message);
    }

    [Fact]
    public void SatCredentials_GetPublicKeyBytesFromPrivateKey_ShouldReturnValidBytes()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);
        var credentials = new SatCredentials(certBytes, keyBytes, keyPassword);

        // Act
        var pubKeyBytes = credentials.PublicKeyBytesFromPrivateKey;

        // Assert
        Assert.NotNull(pubKeyBytes);
        Assert.NotEmpty(pubKeyBytes);
    }

    [Fact]
    public void SatCredentials_GetPublicKeyPemFromPrivateKey_ShouldReturnValidPem()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);
        var credentials = new SatCredentials(certBytes, keyBytes, keyPassword);

        // Act
        var pubKeyPem = credentials.PublicKeyPemFromPrivateKey;

        // Assert
        Assert.NotNull(pubKeyPem);
        Assert.NotEmpty(pubKeyPem);
        Assert.StartsWith("-----BEGIN PUBLIC KEY-----", pubKeyPem);
        Assert.EndsWith("-----END PUBLIC KEY-----", pubKeyPem);
    }

    #endregion

    #region Private Key Tests

    [Fact]
    public void SatCredentials_GetPrivateKeyBytes_ShouldReturnValidBytes()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);
        var credentials = new SatCredentials(certBytes, keyBytes, keyPassword);

        // Act
        var privateKeyBytes = credentials.PrivateKeyBytes;

        // Assert
        Assert.NotNull(privateKeyBytes);
        Assert.NotEmpty(privateKeyBytes);
    }

    [Fact]
    public void SatCredentials_GetRSAPrivateKeyPem_ShouldReturnValidPem()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);
        var credentials = new SatCredentials(certBytes, keyBytes, keyPassword);

        // Act
        var privateKeyPem = credentials.RSAPrivateKeyPem;

        // Assert
        Assert.NotNull(privateKeyPem);
        Assert.NotEmpty(privateKeyPem);
        Assert.StartsWith("-----BEGIN RSA PRIVATE KEY-----", privateKeyPem);
        Assert.EndsWith("-----END RSA PRIVATE KEY-----", privateKeyPem);
    }

    [Fact]
    public void SatCredentials_GetPkcs8PrivateKeyPem_ShouldReturnValidPem()
    {
        // Arrange
        var certFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer");
        var keyFilename = TestUtils.GetTestFilePath("./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key");
        const string keyPassword = "12345678a";
        var certBytes = File.ReadAllBytes(certFilename);
        var keyBytes = File.ReadAllBytes(keyFilename);
        var credentials = new SatCredentials(certBytes, keyBytes, keyPassword);

        // Act
        var pkcs8Pem = credentials.Pkcs8PrivateKeyPem;

        // Assert
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", pkcs8Pem);
        Assert.EndsWith("-----END PRIVATE KEY-----", pkcs8Pem);
    }

    #endregion

}
