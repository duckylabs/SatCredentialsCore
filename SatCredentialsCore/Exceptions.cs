namespace SatCredentialsCore;

public class SatCredentialsError : Exception
{
    public SatCredentialsError(string? message = null, Exception? ex = null) : base(message, ex) { }
}
