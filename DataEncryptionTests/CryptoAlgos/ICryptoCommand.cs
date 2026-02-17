
namespace DataEncryptionTests.CryptoAlgos;

public interface ICryptoCommand
{
    string Key { get; }    
    string Description { get; }  
    Task ExecuteAsync();
}
