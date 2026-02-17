using System;
using System.Security.Cryptography;
using System.Text;

namespace DataEncryptionTests.CryptoAlgos
{
    public class RsaDecryptCommand : ICryptoCommand
    {
        public string Key => "2";
        public string Description => "RSA Decryption";

        public async Task ExecuteAsync()
        {
            try
            {
                Console.Write("Enter RSA Encrypted text: ");
                var data = Console.ReadLine();

                if (string.IsNullOrWhiteSpace(data))
                {
                    Console.WriteLine("❌ No input provided. Returning to menu.");
                    return;
                }

                var encrypted = await Decrypt(data);

                Console.WriteLine("RSA Decrypted:\n\n");
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

        private Task<string> Decrypt(string data)
        {
            if (!File.Exists(Constants.PrivateKeyPath))
                throw new FileNotFoundException();

            using RSA rsaEnc = RSA.Create();

            var pem = File.ReadAllText(Constants.PrivateKeyPath);
            rsaEnc.ImportFromPem(pem);

            byte[] dataArr = Convert.FromBase64String(data);

            byte[] decryptedData = rsaEnc.Decrypt(
                dataArr,
                RSAEncryptionPadding.OaepSHA256);

            return Task.FromResult(Encoding.UTF8.GetString(decryptedData)); ;

        }
    }
}

