using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;

namespace DataEncryptionTests
{
    class LegacyEncryptionEndpointCall
    {
       private async Task AllFunctions()
        {

            var ExtrCert = X509CertificateLoader.LoadCertificateFromFile("G:\\Namu\\docs\\KSACCO\\app_kingdomsacco_com\\app_kingdomsacco_com.crt");
            //var spki = ExtrCert.GetCertHash();
            //using var sha = SHA256.Create();
            //var spkiHash = sha.ComputeHash(spki);
            //var spkiBase64 = Convert.ToBase64String(spkiHash);
            //Console.WriteLine(spkiBase64);

            var clientCertificate = X509CertificateLoader.LoadPkcs12FromFile(
                "G:\\Namu\\docs\\KSACCO\\app_kingdomsacco_com\\app_kingdomsacco_com.pfx",
                "KINGjog288",
                X509KeyStorageFlags.Exportable |
                X509KeyStorageFlags.MachineKeySet |
                X509KeyStorageFlags.PersistKeySet);



            using var rsa = clientCertificate.GetRSAPublicKey();

            var jsonPayload = File.ReadAllText("E:\\certificates\\payload.txt");

            // Encrypt payload
            using RSA rsaEnc = RSA.Create();
            rsaEnc.ImportFromPem(File.ReadAllText("G:\\Namu\\docs\\KSACCO\\pem\\public.pem"));
            var encryptedData = rsaEnc.Encrypt(Encoding.UTF8.GetBytes(jsonPayload), RSAEncryptionPadding.Pkcs1);
            var base64Encrypted = Convert.ToBase64String(encryptedData);

            // Configure handler

            var handler = new HttpClientHandler();
            var flags = X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable;
            //var cert = new X509Certificate2("G:\\Namu\\docs\\KSACCO\\app_kingdomsacco_com\\app_kingdomsacco_com.pfx", "KINGjog288", flags);

            var cert = new X509Certificate2("G:\\Namu\\docs\\KSACCO\\app_kingdomsacco_com\\ksaccotestcerts.pfx", "KINGjog287", flags);

            var pinnedCert = X509CertificateLoader
                .LoadPkcs12FromFile("G:\\Namu\\docs\\KSACCO\\app_kingdomsacco_com\\ksaccotestcerts.pfx", "KINGjog287", flags);
            //var pinnedCert = X509CertificateLoader.LoadPkcs12FromFile("G:\\Namu\\docs\\KSACCO\\app_kingdomsacco_com\\ksaccotestcerts.pfx", "KINGjog287",
            //                              X509KeyStorageFlags.UserKeySet |
            //                              X509KeyStorageFlags.PersistKeySet |
            //                              X509KeyStorageFlags.Exportable
            //                          );

            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
            handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

            handler.ClientCertificates.Add(pinnedCert);

            // (optional) allow only strong TLS versions

            // Send request
            using var client = new HttpClient(handler);
            var content = new StringContent(base64Encrypted, Encoding.UTF8, "application/json"); // Send as plain text
            var response = await client.PostAsync("https://localhost:6738/api/_hc", content);
            //response.EnsureSuccessStatusCode();

            // Read and decrypt response
            var encryptedResponse = await response.Content.ReadAsStringAsync();
            var dataToDecrypt = Convert.FromBase64String(encryptedResponse);
            // You cannot decrypt with the public key. This is a simplification.
            // The client would use its own private key if the server used the client's public key.
            // For this example's symmetry, let's assume the server encrypted with its private key,
            // so we can decrypt with the public key.
            rsaEnc.ImportFromPem(File.ReadAllText("G:\\Namu\\docs\\KSACCO\\pem\\private.pem"));
            var decryptedBytes = rsaEnc.Decrypt(dataToDecrypt, RSAEncryptionPadding.Pkcs1);

            Console.WriteLine(Encoding.UTF8.GetString(decryptedBytes));
        }
    }
 }

