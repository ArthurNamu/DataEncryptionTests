// Load ONLY the public key on the client side
using DataEncryptionTests.CryptoAlgos;
using System.Security.Cryptography;
using System.Text;

var commands = new List<ICryptoCommand>
        {
            new RsaEncryptCommand(),
            new RsaDecryptCommand(),
            new HybridEncryptCommand(),
            new HybridDecryptCommand(),
            new SignDataCommand()
        };
var map = commands.ToDictionary(c => c.Key);

while (true)
{
    PrintMenu(commands);

    Console.Write("Select: ");
    var choice = Console.ReadLine();

    if (choice == "0")
        break;

    if (map.TryGetValue(choice, out var command))
    {
        try
        {
            await command.ExecuteAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
    else
    {
        Console.WriteLine("Invalid selection");
    }

    Console.WriteLine();
}


static void PrintMenu(IEnumerable<ICryptoCommand> commands)
{
    Console.WriteLine("====== Crypto Tool ======");

    foreach (var cmd in commands)
        Console.WriteLine($"{cmd.Key}. {cmd.Description}");

    Console.WriteLine("0. Exit");
}
Console.ReadLine();

