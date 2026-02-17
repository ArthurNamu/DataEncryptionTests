namespace DataEncryptionTests.Utils;

public static class UtilityTool
{
   public static bool IsBase64String(string input)
    {
        // Rough check for Base64 validity
        Span<byte> buffer = new Span<byte>(new byte[input.Length]);
        return Convert.TryFromBase64String(input, buffer, out _);
    }
}
