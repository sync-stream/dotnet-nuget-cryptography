// Define our namespace
namespace SyncStream.Cryptography;

/// <summary>
/// This class maintains the structure of our cryptography exception
/// </summary>
public class CryptographyException : Exception
{
    /// <summary>
    /// This method instantiates our exception with an optional message and optional inner exception
    /// </summary>
    /// <param name="message">Optional message to describe the exception</param>
    /// <param name="innerException">Optional source of the exception</param>
    public CryptographyException(string message = null, Exception innerException = null) : base(message, innerException) { }
}
