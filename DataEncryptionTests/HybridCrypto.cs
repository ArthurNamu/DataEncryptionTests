
using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace DataEncryptionTests;

public static class HybridCrypto
{
    public static (byte[] EncryptedKey, byte[] IV, byte[] CipherText) Encrypt(string plaintext, RSA rsaPublicKey)
    {



        // 1️⃣ Create AES key
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();

        // 2️⃣ Encrypt message with AES
        using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream();
        using (var cryptoStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            var bytes = Encoding.UTF8.GetBytes(plaintext);
            cryptoStream.Write(bytes, 0, bytes.Length);
        }
        byte[] cipherText = ms.ToArray();

        // 3️⃣ Encrypt AES key with RSA
        byte[] encryptedKey = rsaPublicKey.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);

        return (encryptedKey, aes.IV, cipherText);
    }


    public static string  Encrypt(string plainText, string publicKeyPem)
    {
        // 1. Generate AES key
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.GenerateKey();
        aes.GenerateIV();

        // 2. Encrypt the message using AES
        var encryptor = aes.CreateEncryptor();
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var encryptedDataBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        var encryptedData = Convert.ToBase64String(encryptedDataBytes);

        // 3. Encrypt AES key using RSA Public Key
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);
        var encryptedKeyBytes = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
        var encryptedKey = Convert.ToBase64String(encryptedKeyBytes);

        // Return what you can store or send over network

        var result = JsonSerializer.Serialize(
            new EncryptedPayload { EncryptedData = encryptedData, EncryptedKey = encryptedKey, IV = Convert.ToBase64String(aes.IV) });

        return (result);
    }


    public static string Decrypt(string jsonPayload, string privateKeyPem)
    {

        var payload = JsonSerializer.Deserialize<EncryptedPayload>(jsonPayload)
                     ?? throw new InvalidOperationException("Invalid encrypted payload format");

        // 1. Decrypt AES key using RSA Private Key
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);
        var decryptedKey = rsa.Decrypt(Convert.FromBase64String(payload.EncryptedKey), RSAEncryptionPadding.OaepSHA256);

        // 2. Decrypt data using AES
        using var aes = Aes.Create();
        aes.Key = decryptedKey;
        aes.IV = Convert.FromBase64String(payload.IV);

        var decryptor = aes.CreateDecryptor();
        var encryptedBytes = Convert.FromBase64String(payload.EncryptedData);
        var decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);

        return Encoding.UTF8.GetString(decryptedBytes);
    }
}

public class EncryptedPayload
{
    public string EncryptedKey { get; set; } = string.Empty;
    public string EncryptedData { get; set; } = string.Empty;
    public string IV { get; set; } = string.Empty;
}


