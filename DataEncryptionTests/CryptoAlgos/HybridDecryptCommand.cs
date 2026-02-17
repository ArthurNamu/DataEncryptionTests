using DataEncryptionTests.Model;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DataEncryptionTests.CryptoAlgos
{
    public class HybridDecryptCommand : ICryptoCommand
    {
        public string Key => "4";
        public string Description => "Hybrid Decryption";

        public async Task ExecuteAsync()
        {
            try
            {
                Console.Write("Enter encrypted text: ");
                var data = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(data))
                {
                    Console.WriteLine("❌ No input provided. Returning to menu.");
                    return;
                }

                var encrypted = await Decrypt(data);

                Console.WriteLine("Decrypted:\n\n");
                Console.WriteLine(encrypted);
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("❌ Private key file not found.");
            }
            catch (CryptographicException ex)
            {
                Console.WriteLine($"❌ Crypto error: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Unexpected error: {ex.Message}");
            }
        }

        public Task<string> Decrypt(string jsonPayload)
        {

            var payload = JsonSerializer.Deserialize<EncryptedPayload>(jsonPayload)
                      ?? throw new InvalidOperationException("Invalid encrypted payload format");

            using var rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(Constants.PrivateKeyPath));
            var decryptedKey = rsa.Decrypt(Convert.FromBase64String(payload.EncryptedKey), RSAEncryptionPadding.OaepSHA256);

            using var aes = Aes.Create();
            aes.Key = decryptedKey;
            aes.IV = Convert.FromBase64String(payload.IV);

            var decryptor = aes.CreateDecryptor();
            var encryptedBytes = Convert.FromBase64String(payload.EncryptedData);
            var decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

            return Task.FromResult(Encoding.UTF8.GetString(decryptedBytes));
        }
    }
}

