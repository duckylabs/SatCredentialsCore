using SatCredentialsCore;

namespace SatCredentialsCoreTests.TestData;

using System.Collections;

public class ValidSATFilesTestData : IEnumerable<object[]>
{
    public IEnumerator<object[]> GetEnumerator()
    {
        yield return new object[] {
            "./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer",
            "./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key",
            "12345678a",
        };
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}


public class ValidCertificatesTestData : IEnumerable<object[]>
{
    public IEnumerator<object[]> GetEnumerator()
    {
        yield return new object[] {
            "./Resources/certs/CACX7605101P8/csd_CACX7605101P8.cer",
            "./Resources/certs/CACX7605101P8/csd_CACX7605101P8.key",
            "12345678a",
            SatCredentialsConstants.CertificateType.CSD,
            SatCredentialsConstants.TaxpayerType.FISICA,
            "",
            "CACX7605101P8",
            "",
            "CACX760510MGTSHC04",
            "",
            "XOCHILT CASAS CHAVEZ",
            "30001000000500003316",
            true,
            "Sucirsa 1",
        };
        yield return new object[] {
            "./Resources/certs/CACX7605101P8/fiel_CACX7605101P8.cer",
            "./Resources/certs/CACX7605101P8/fiel_CACX7605101P8.key",
            "12345678a",
            SatCredentialsConstants.CertificateType.FIEL,
            SatCredentialsConstants.TaxpayerType.FISICA,
            "pruebas@pruebas.gob.mx",
            "CACX7605101P8",
            "",
            "CACX760510MGTSHC04",
            "",
            "XOCHILT CASAS CHAVEZ",
            "30001000000500003282",
            true,
            ""
        };
        yield return new object[] {
            "./Resources/certs/EKU9003173C9/csd_EKU9003173C9.cer",
            "./Resources/certs/EKU9003173C9/csd_EKU9003173C9.key",
            "12345678a",
            SatCredentialsConstants.CertificateType.CSD,
            SatCredentialsConstants.TaxpayerType.MORAL,
            "",
            "EKU9003173C9",
            "VADA800927DJ3",
            "",
            "VADA800927HSRSRL05",
            "ESCUELA KEMPER URGATE",
            "30001000000500003416",
            true,
            "Sucursal 1"
        };
        yield return new object[] {
            "./Resources/certs/EKU9003173C9/fiel_EKU9003173C9.cer",
            "./Resources/certs/EKU9003173C9/fiel_EKU9003173C9.key",
            "12345678a",
            SatCredentialsConstants.CertificateType.FIEL,
            SatCredentialsConstants.TaxpayerType.MORAL,
            "SATpruebas@pruebas.gob.mx",
            "EKU9003173C9",
            "VADA800927DJ3",
            "",
            "VADA800927HSRSRL05",
            "ESCUELA KEMPER URGATE",
            "30001000000500003415",
            true,
            ""
        };
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

