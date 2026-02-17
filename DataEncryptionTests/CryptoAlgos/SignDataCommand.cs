using System;
using System.Security.Cryptography;
using System.Text;

namespace DataEncryptionTests.CryptoAlgos
{
    public class SignDataCommand : ICryptoCommand
    {
        public string Key => "5";
        public string Description => "Sign Data";

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

                var encrypted = await SignData(data);

                Console.WriteLine("Signed:\n\n");
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

        public Task<string> SignData(string plainText)
        {
            byte[] dataToSign = Encoding.UTF8.GetBytes(plainText);

            using (RSA rsa = RSA.Create())
            {
                rsa.ImportFromPem(Constants.PrivateKeyPath.ToCharArray());

                byte[] signature = rsa.SignData(
                    dataToSign,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1
                );

                return Task.FromResult(Convert.ToBase64String(signature));
            }
        }
    }
}

