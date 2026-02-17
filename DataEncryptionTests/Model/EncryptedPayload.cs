namespace DataEncryptionTests.Model;

public class EncryptedPayload
{
    public string EncryptedKey { get; set; } = string.Empty;
    public string EncryptedData { get; set; } = string.Empty;
    public string IV { get; set; } = string.Empty;
}


