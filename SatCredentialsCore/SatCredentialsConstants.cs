namespace SatCredentialsCore;

public static class SatCredentialsConstants
{
    public enum CertificateType {
        CSD, FIEL
    }

    public enum TaxpayerType {
        FISICA, MORAL
    }

    public static readonly Dictionary<string, string> RegimenesSocietarios = new()
    {
        {"AC", "AC - Asociación civil"},
        {"S DE CV", "Sociedad de capital variable"},
        {"S DE RL DE CV", "Sociedad de responsabilidad limitada de capital variable"},
        {"S DE RL", "Sociedad de responsabilidad limitada"},
        {"S EN C DE CV", "Sociedad en comandita simple de capital variable"},
        {"S EN C POR A DE CV", "Sociedad en comandita por acciones de capital variable"},
        {"S EN C POR A", "Sociedad en comandita por acciones"},
        {"S EN C", "Sociedad en comandita simple"},
        {"S EN NC DE CV", "Sociedad en nombre colectivo de capital variable"},
        {"S EN NC", "Sociedad en nombre colectivo"},
        {"SA DE CV", "Sociedad anónima de capital variable"},
        {"SA", "Sociedad anónima"},
        {"SAB DE CV", "Sociedad anómina bursátil de capital variable"},
        {"SAB", "Sociedad anómina bursátil"},
        {"SAPI DE CV", "Sociedad anónima promotora de inversión de capital variable"},
        {"SAPI", "Sociedad anónima promotora de inversión"},
        {"SAPIB", "Sociedad anónima promotora de inversión bursátil"},
        {"SAS DE CV", "Sociedad por acciones simplificada de capital variable"},
        {"SAS", "Sociedad por acciones simplificada"},
        {"SC DE CV", "Sociedad civil de capital variable"},
        {"SC", "Sociedad civil"},
    };
}