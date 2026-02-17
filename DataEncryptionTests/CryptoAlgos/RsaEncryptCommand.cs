using System;
using System.Security.Cryptography;
using System.Text;

namespace DataEncryptionTests.CryptoAlgos
{
    public class RsaEncryptCommand : ICryptoCommand
    {
        public string Key => "1";
        public string Description => "RSA Encryption";

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

        private Task<string> Encrypt(string data)
        {
            if (!File.Exists(Constants.PublicKeyPath))
                throw new FileNotFoundException();

            using RSA rsaEnc = RSA.Create();

            var pem = File.ReadAllText(Constants.PublicKeyPath);
            rsaEnc.ImportFromPem(pem);

            byte[] dataArr = Encoding.UTF8.GetBytes(data);

            byte[] encryptedData = rsaEnc.Encrypt(
                dataArr,
                RSAEncryptionPadding.OaepSHA256);

            return Task.FromResult(Convert.ToBase64String(encryptedData));
        }
    }
}

