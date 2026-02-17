using DataEncryptionTests.Model;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DataEncryptionTests.CryptoAlgos
{
    public class HybridEncryptCommand : ICryptoCommand
    {
        public string Key => "3";
        public string Description => "Hybrid Encryption";

        public async Task ExecuteAsync()
        {
            try
            {
                Console.Write("Enter plaintext: ");
                var data = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(data))
                {
                    Console.WriteLine("❌ No input provided. Returning to menu.");
                    return;
                }

                var encrypted = await Encrypt(data);

                Console.WriteLine("Encrypted:\n\n");
                Console.WriteLine(encrypted);
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("❌ Public key file not found.");
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

        private Task<string> Encrypt(string plainText)
        {
            using var aes = Aes.Create();
            aes.KeySize = 256;
            aes.GenerateKey();
            aes.GenerateIV();

            var encryptor = aes.CreateEncryptor();
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var encryptedDataBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
            var encryptedData = Convert.ToBase64String(encryptedDataBytes);

            using var rsa = RSA.Create();
            rsa.ImportFromPem(File.ReadAllText(Constants.PublicKeyPath));
            var encryptedKeyBytes = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
            var encryptedKey = Convert.ToBase64String(encryptedKeyBytes);

            var result = JsonSerializer.Serialize(
                new EncryptedPayload { EncryptedData = encryptedData, EncryptedKey = encryptedKey, IV = Convert.ToBase64String(aes.IV) });

            return Task.FromResult((result));
        }
    }
}

