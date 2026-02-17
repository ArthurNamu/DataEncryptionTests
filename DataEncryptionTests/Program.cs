// Load ONLY the public key on the client side
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.ConstrainedExecution;
using DataEncryptionTests;

Console.WriteLine("=== RSA Encrypt/Decrypt Tool ===\n");


//For hybrid cache starts here......
string publicKeyPem = File.ReadAllText("D:\\Namu\\docs\\KSACCO\\pem\\public.pem");
using var rsaPublic = RSA.Create();
rsaPublic.ImportFromPem(publicKeyPem);

// Load your RSA private key (for decryption)
string privateKeyPem = File.ReadAllText("D:\\Namu\\docs\\KSACCO\\pem\\private.pem");
using var rsaPrivate = RSA.Create();
rsaPrivate.ImportFromPem(privateKeyPem);


Console.ReadLine();

while (true)
{
    Console.Write("Enter text (or press Enter to exit): ");
    string input = Console.ReadLine();

    if (string.IsNullOrWhiteSpace(input))
        break;

    try
    {
        if (!IsBase64String(input))
        //if (IsForDecryption(input))
        {
            Console.WriteLine("\nDetected Base64 input — decrypting...\n");

            //var decrypted = HybridCrypto.Decrypt(input, privateKeyPem);

            string decrypted = DecryptBase64(input);
            Console.WriteLine("Decrypted Text:\n" + decrypted);
        }
        else
        {
            Console.WriteLine("\nDetected plain text/JSON — encrypting...\n");

            //string encrypted = HybridCrypto.Encrypt(input, publicKeyPem);

            string encrypted = EncryptToBase64(input);

            Console.WriteLine("Encrypted Base64:\n" + encrypted);
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"❌ Error: {ex.Message}");
    }

    Console.WriteLine("\n--------------------------------------\n");
}


static bool IsBase64String(string input)
{
    // Rough check for Base64 validity
    Span<byte> buffer = new Span<byte>(new byte[input.Length]);
    return Convert.TryFromBase64String(input, buffer, out _);
}

//static bool IsForDecryption(string input)
//{
//    return input.Contains("EncryptedData");
//}

PrintMenu

static string EncryptToBase64(string plainText)
{
    using RSA rsaEnc = RSA.Create();
    rsaEnc.ImportFromPem(File.ReadAllText("D:\\Namu\\docs\\KSACCO\\pem\\public.pem"));

    byte[] data = Encoding.UTF8.GetBytes(plainText);
    byte[] encryptedData = rsaEnc.Encrypt(data, RSAEncryptionPadding.OaepSHA256);

    return Convert.ToBase64String(encryptedData);
}

static string DecryptBase64(string base64Input)
{
    byte[] dataToDecrypt = Convert.FromBase64String(base64Input);

    using RSA rsaDec = RSA.Create();
    rsaDec.ImportFromPem(File.ReadAllText("D:\\Namu\\docs\\KSACCO\\pem\\private.pem"));

    byte[] decrypted = rsaDec.Decrypt(
        dataToDecrypt,
        RSAEncryptionPadding.OaepSHA256
    );

    return Encoding.UTF8.GetString(decrypted);
}


