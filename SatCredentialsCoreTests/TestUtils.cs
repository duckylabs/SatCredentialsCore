using System.Runtime.CompilerServices;

namespace SatCredentialsCoreTests;

public class TestUtils
{
    public static string GetTestFilePath(string filename, [CallerFilePath] string filePath = "")
    {
        var directoryPath = Path.GetDirectoryName(filePath);
        return Path.Join(directoryPath, filename);
    }
}