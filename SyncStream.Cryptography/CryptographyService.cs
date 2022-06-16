using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using SyncStream.Serializer;

// Define our namespace
namespace SyncStream.Cryptography;

/// <summary>
/// This class provides cryptographic routines for AES-256 standard encryption
/// </summary>
public static class CryptographyService
{
    /// <summary>
    /// This property contains the key to use for encryption and decryption by default
    /// </summary>
    public static readonly string Key = Environment.GetEnvironmentVariable("SS_CRYPTO_KEY");

    /// <summary>
    /// This property contains the number of passes to redundantly encrypt by default
    /// </summary>
    public static readonly int Passes = int.Parse(Environment.GetEnvironmentVariable("SS_CRYPTO_PASSES") ?? "16");

    /// <summary>
    /// This method ensures that the key and number of passes are always present
    /// </summary>
    /// <param name="key">The secret key with which to decrypt or encrypt values</param>
    /// <param name="passes">The number of recursive decryption passes to run</param>
    /// <returns>An awaitable task containing the decrypted value</returns>
    private static void EnsureCryptographicRequirements(ref string key, ref int? passes)
    {
        // Check the value of the key
        if (string.IsNullOrEmpty(key) || string.IsNullOrWhiteSpace(key))
            // Reset the key to the instance default
            key = Key;
        // Check the value of the passes
        if (!passes.HasValue || passes.Value < 0)
            // Reset the passes to the instance default
            passes = Passes;
    }

    /// <summary>
    /// This method determines whether <paramref name="value" /> is XML or not
    /// </summary>
    /// <param name="value">The string value to check</param>
    /// <returns>A boolean denoting the whether <paramref name="value" /> is XML or not</returns>
    private static bool IsXml(string value) =>
        value?.TrimStart().StartsWith('<') ?? false;

    /// <summary>
    /// This method decrypts a hash from this library and returns the expected value as a <code>string</code>
    /// </summary>
    /// <param name="hash">The encrypted hash to decrypt</param>
    /// <param name="key">Optional secret key with which to decrypt the value</param>
    /// <returns>The decrypted value</returns>
    public static string Decrypt(string hash, string key = null)
    {
        // Validate the hash
        Match match = ValidateHash(hash, true);

        // Localize the number of passes
        int passes = Convert.ToInt32(match.Groups[1].Value);

        // Localize the actual hash
        hash = match.Groups[match.Groups.Count].Value;

        // Return the decrypted value
        return DecryptExternal(hash, key, passes);
    }

    /// <summary>
    /// This method decrypts a hash from this library, deserializes it and returns the <typeparamref name="TTarget" /> object
    /// </summary>
    /// <param name="hash">The encrypted hash to decrypt</param>
    /// <param name="key">Optional secret key with which to decrypt the value</param>
    /// <param name="defaultFormat">Optional serialization format to use if the hash doesn't contain one</param>
    /// <typeparam name="TTarget">The type to deserialize the object into</typeparam>
    /// <returns>The decrypted and deserialized object</returns>
    public static TTarget Decrypt<TTarget>(string hash, string key = null,
        SerializerFormat defaultFormat = SerializerFormat.Json) where TTarget : class, new()
    {
        // Validate the hash
        Match match = ValidateHash(hash, true);

        // Localize the number of passes
        int passes = Convert.ToInt32(match.Groups[1].Value);

        // Localize the actual hash
        hash = match.Groups[match.Groups.Count].Value;

        // Decrypt the value
        string value = DecryptExternal(hash, key, passes);

        // Define our serialization format
        SerializerFormat format = defaultFormat;

        // Check for a provided format in the hash
        if (match.Groups.Count is 4) format = Enum.Parse<SerializerFormat>(match.Groups[3].Value, true);

        // We're done, return the deserialized object
        return format is SerializerFormat.Xml
            ? XmlSerializer.Deserialize<TTarget>(value)
            : JsonSerializer.Deserialize<TTarget>(value);
    }

    /// <summary>
    /// This method asynchronously decrypts a hash from this library and returns the expected value as a <code>string</code>
    /// </summary>
    /// <param name="hash">The encrypted hash to decrypt</param>
    /// <param name="key">Optional secret key with which to decrypt the value</param>
    /// <returns>An awaitable task containing the decrypted value</returns>
    public static Task<string> DecryptAsync(string hash, string key = null)
    {
        // Validate the hash
        Match match = ValidateHash(hash, true);

        // Localize the number of passes
        int passes = Convert.ToInt32(match.Groups[1].Value);

        // Localize the actual hash
        hash = match.Groups[3].Value;

        // Return the decrypted value
        return DecryptExternalAsync(hash, key, passes);
    }

    /// <summary>
    /// This method asynchronously decrypts a hash from this library, deserializes it and returns the <typeparamref name="TTarget" /> object
    /// </summary>
    /// <param name="hash">The encrypted hash to decrypt</param>
    /// <param name="key">Optional secret key with which to decrypt the value</param>
    /// <param name="defaultFormat">Optional serialization format to use if the hash doesn't contain one</param>
    /// <typeparam name="TTarget">The type to deserialize the object into</typeparam>
    /// <returns>An awaitable task containing the decrypted and deserialized object</returns>
    public static async Task<TTarget> DecryptAsync<TTarget>(string hash, string key = null,
        SerializerFormat defaultFormat = SerializerFormat.Json) where TTarget : class, new()
    {
        // Validate the hash
        Match match = ValidateHash(hash, true);

        // Localize the number of passes
        int passes = Convert.ToInt32(match.Groups[1].Value);

        // Localize the actual hash
        hash = match.Groups[match.Groups.Count].Value;

        // Decrypt the value
        string value = await DecryptExternalAsync(hash, key, passes);

        // Define our serialization format
        SerializerFormat format = defaultFormat;

        // Check for a provided format in the hash
        if (match.Groups.Count is 4) format = Enum.Parse<SerializerFormat>(match.Groups[3].Value, true);

        // We're done, return the deserialized object
        return format is SerializerFormat.Xml
            ? XmlSerializer.Deserialize<TTarget>(value)
            : JsonSerializer.Deserialize<TTarget>(value);
    }

    /// <summary>
    /// This method decrypts an external hash that has used the AES-256 standard to encrypt it and returns the resulting value as a <code>string</code>
    /// </summary>
    /// <param name="hash">The encrypted hash to decrypt</param>
    /// <param name="passes">Optional number of recursive decryption passes to run</param>
    /// <param name="key">Optional secret key with which to decrypt the value</param>
    /// <returns>The decrypted value</returns>
    public static string DecryptExternal(string hash, string key = null, int? passes = null) =>
        DecryptExternal(Convert.FromBase64String(hash), key, passes);

    /// <summary>
    /// This method asynchronously decrypts an external hash that has used the AES-256 standard to encrypt it and returns the resulting value as a <code>string</code>
    /// </summary>
    /// <param name="hash">The encrypted hash to decrypt</param>
    /// <param name="passes">Optional number of recursive decryption passes to run</param>
    /// <param name="key">Optional secret key with which to decrypt the value</param>
    /// <returns>An awaitable task containing the decrypted value</returns>
    public static Task<string> DecryptExternalAsync(string hash, string key = null, int? passes = null) =>
        DecryptExternalAsync(Convert.FromBase64String(hash), key, passes);

    /// <summary>
    /// This method decrypts an external byte array that has used the AES-256 standard to encrypt it and returns the resulting value as a <code>string</code>
    /// </summary>
    /// <param name="hash">The encrypted hash to decrypt</param>
    /// <param name="passes">Optional number of recursive decryption passes to run</param>
    /// <param name="key">Optional secret key with which to decrypt the value</param>
    /// <returns>The decrypted value</returns>
    public static string DecryptExternal(byte[] hash, string key = null, int? passes = null)
    {
        // Make sure the cryptographic requirements exit
        EnsureCryptographicRequirements(ref key, ref passes);

        // Define our result
        byte[] result = hash;

        // Iterate to our pass
        for (int pass = 0; pass < passes; ++pass)
        {
            // Define our cryptographic service provider
            using SHA512CryptoServiceProvider provider = new SHA512CryptoServiceProvider();

            // Define our AES key
            byte[] aesKey = new byte[32];

            // Compute the cryptographic hash
            Buffer.BlockCopy(provider.ComputeHash(Encoding.UTF8.GetBytes(key)), 0, aesKey, 0, 32);

            // Generate our AES engine
            using Aes aes = Aes.Create();

            // Make sure we have a valid engine
            if (aes == null) throw new CryptographyException("Unable to instantiate AES Cryptographic Engine");

            // Set our key into the engine
            aes.Key = aesKey;

            // Define our initialization vector
            byte[] initializationVector = new byte[aes.IV.Length];
            // Define our cipher text
            byte[] cipher = new byte[result.Length - initializationVector.Length];

            // Localize the initialization vector
            Array.ConstrainedCopy(result, 0, initializationVector, 0, initializationVector.Length);
            // Localize the cipher
            Array.ConstrainedCopy(result, initializationVector.Length, cipher, 0, cipher.Length);

            // Set the initialization vector into the engine
            aes.IV = initializationVector;

            // Define our engine and isolate
            using ICryptoTransform transform = aes.CreateDecryptor(aes.Key, aes.IV);
            // Define our result stream and isolate
            using MemoryStream resultStream = new MemoryStream();
            // Define our cryptographic stream and isolate
            using CryptoStream aesStream = new CryptoStream(resultStream, transform, CryptoStreamMode.Write);
            // Define our plain text stream and isolate
            using MemoryStream finalStream = new MemoryStream(cipher);

            // Decrypt the cipher
            finalStream.CopyTo(aesStream);

            // Reset the result
            result = resultStream.ToArray();
        }

        // We're done, return the decrypted value
        return Encoding.UTF8.GetString(result);
    }

    /// <summary>
    /// This method asynchronously decrypts an external byte array that has used the AES-256 standard to encrypt it and returns the resulting value as a <code>string</code>
    /// </summary>
    /// <param name="hash">The encrypted hash to decrypt</param>
    /// <param name="passes">Optional number of recursive decryption passes to run</param>
    /// <param name="key">Optional secret key with which to decrypt the value</param>
    /// <returns>An awaitable task containing the decrypted value</returns>
    public static async Task<string> DecryptExternalAsync(byte[] hash, string key = null, int? passes = null)
    {
        // Make sure the cryptographic requirements exit
        EnsureCryptographicRequirements(ref key, ref passes);

        // Define our result
        byte[] result = hash;

        // Iterate to our pass
        for (int pass = 0; pass < passes; ++pass)
        {
            // Define our cryptographic service provider
            using SHA512CryptoServiceProvider provider = new SHA512CryptoServiceProvider();

            // Define our AES key
            byte[] aesKey = new byte[32];

            // Compute the cryptographic hash
            Buffer.BlockCopy(provider.ComputeHash(Encoding.UTF8.GetBytes(key)), 0, aesKey, 0, 32);

            // Generate our AES engine
            using Aes aes = Aes.Create();

            // Make sure we have a valid engine
            if (aes == null) throw new CryptographyException("Unable to instantiate AES Cryptographic Engine");

            // Set our key into the engine
            aes.Key = aesKey;

            // Define our initialization vector
            byte[] initializationVector = new byte[aes.IV.Length];
            // Define our cipher text
            byte[] cipher = new byte[result.Length - initializationVector.Length];

            // Localize the initialization vector
            Array.ConstrainedCopy(result, 0, initializationVector, 0, initializationVector.Length);
            // Localize the cipher
            Array.ConstrainedCopy(result, initializationVector.Length, cipher, 0, cipher.Length);

            // Set the initialization vector into the engine
            aes.IV = initializationVector;

            // Define our engine and isolate
            using ICryptoTransform transform = aes.CreateDecryptor(aes.Key, aes.IV);
            // Define our result stream and isolate
            await using MemoryStream resultStream = new MemoryStream();
            // Define our cryptographic stream and isolate
            await using CryptoStream aesStream = new CryptoStream(resultStream, transform, CryptoStreamMode.Write);
            // Define our plain text stream and isolate
            await using MemoryStream finalStream = new MemoryStream(cipher);

            // Decrypt the cipher
            await finalStream.CopyToAsync(aesStream);

            // Reset the result
            result = resultStream.ToArray();
        }

        // We're done, return the decrypted value
        return Encoding.UTF8.GetString(result);
    }

    /// <summary>
    /// This method encrypts a value redundantly then returns the Base64 string value of the hash
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <param name="passes">Optional number of recursive encryption passes to run</param>
    /// <param name="key">Optional secret key with which to encrypt the value</param>
    /// <param name="format">Optional serialization format</param>
    /// <returns>The encrypted hash of <paramref name="value" /></returns>
    public static string Encrypt(object value, int? passes = null, string key = null, SerializerFormat? format = null)
    {
        // Make sure the key and passes are valid
        EnsureCryptographicRequirements(ref key, ref passes);

        // Define our cryptographic service provider
        using SHA512CryptoServiceProvider provider = new SHA512CryptoServiceProvider();

        // Define our AES key
        byte[] aesKey = new byte[32];

        // Compute the cryptographic hash
        Buffer.BlockCopy(provider.ComputeHash(Encoding.UTF8.GetBytes(key)), 0, aesKey, 0, 32);

        // Instantiate our AES cryptographic system provider
        using Aes aes = Aes.Create();

        // Encrypt and encode the value
        string hash = Convert.ToBase64String(EncryptExternalRaw(value, passes, key));

        // We're done, return the results
        return format is null
            ? $"{{AES}}${passes}${aes.IV.Length}${hash}"
            : $"{{AES}}${passes}${aes.IV.Length}${format.Value.ToString().ToUpper()}${hash}";
    }

    /// <summary>
    /// This method asynchronously serializes an object and encrypts its serialized value
    /// </summary>
    /// <param name="value">The object to serialize and encrypt</param>
    /// <param name="format">Optional format in which to serialize the object value</param>
    /// <param name="passes">Optional number of recursive encryption passes to run</param>
    /// <param name="key">Optional secret key with which to encrypt the value</param>
    /// <typeparam name="TSource"></typeparam>
    /// <returns>An awaitable task containing the encrypted hash of <paramref name="value" /></returns>
    public static string Encrypt<TSource>(TSource value, SerializerFormat format = SerializerFormat.Json,
        int? passes = null, string key = null) where TSource : class, new() => Encrypt(
        format is SerializerFormat.Xml ? XmlSerializer.Serialize(value) : JsonSerializer.Serialize(value), passes, key,
        format);

    /// <summary>
    /// This method encrypts a value redundantly and asynchronously then returns the Base64 string value of the hash
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <param name="passes">Optional number of recursive encryption passes to run</param>
    /// <param name="key">Optional secret key with which to encrypt the value</param>
    /// <param name="format"></param>
    /// <returns>An awaitable task containing the encrypted hash of <paramref name="value" /></returns>
    public static async Task<string> EncryptAsync(object value, int? passes = null, string key = null,
        SerializerFormat? format = null)
    {
        // Make sure the key and passes are valid
        EnsureCryptographicRequirements(ref key, ref passes);

        // Define our cryptographic service provider
        using SHA512CryptoServiceProvider provider = new SHA512CryptoServiceProvider();

        // Define our AES key
        byte[] aesKey = new byte[32];

        // Compute the cryptographic hash
        Buffer.BlockCopy(provider.ComputeHash(Encoding.UTF8.GetBytes(key)), 0, aesKey, 0, 32);

        // Instantiate our AES cryptographic system provider
        using Aes aes = Aes.Create();

        // Encrypt and encode the value
        string hash = Convert.ToBase64String(await EncryptExternalRawAsync(value, passes, key));

        // We're done, return the results
        return format is null
            ? $"{{AES}}${passes}${aes.IV.Length}${hash}"
            : $"{{AES}}${passes}${aes.IV.Length}${format.Value.ToString().ToUpper()}${hash}";
    }

    /// <summary>
    /// This method asynchronously serializes an object and encrypts its serialized value
    /// </summary>
    /// <param name="value">The object to serialize and encrypt</param>
    /// <param name="format">Optional format in which to serialize the object value</param>
    /// <param name="passes">Optional number of recursive encryption passes to run</param>
    /// <param name="key">Optional secret key with which to encrypt the value</param>
    /// <typeparam name="TSource"></typeparam>
    /// <returns>An awaitable task containing the encrypted hash of <paramref name="value" /></returns>
    public static Task<string> EncryptAsync<TSource>(TSource value, SerializerFormat format = SerializerFormat.Json,
        int? passes = null, string key = null) where TSource : class, new() => EncryptAsync(
        format is SerializerFormat.Xml ? XmlSerializer.Serialize(value) : JsonSerializer.Serialize(value), passes, key,
        format);

    /// <summary>
    /// This method encrypts a value into a Base64 encoded representation with no library identifiers in the hash
    /// </summary>
    /// <param name="value">The object to serialize and encrypt</param>
    /// <param name="passes">Optional number of recursive encryption passes to run</param>
    /// <param name="key">Optional secret key with which to encrypt the value</param>
    /// <returns>The encrypted hash of <paramref name="value" /></returns>
    public static string EncryptExternal(object value, int? passes = null, string key = null) =>
        Convert.ToBase64String(EncryptExternalRaw(value, passes, key));

    /// <summary>
    /// This asynchronously method encrypts a value into a Base64 encoded representation with no library identifiers in the hash
    /// </summary>
    /// <param name="value">The object to serialize and encrypt</param>
    /// <param name="passes">Optional number of recursive encryption passes to run</param>
    /// <param name="key">Optional secret key with which to encrypt the value</param>
    /// <returns>An awaitable task containing the encrypted hash of <paramref name="value" /></returns>
    public static async Task<string> EncryptExternalAsync(object value, int? passes = null, string key = null) =>
        Convert.ToBase64String(await EncryptExternalRawAsync(value, passes, key));

    /// <summary>
    /// This method encrypts a value with no library identifiers in the hash
    /// </summary>
    /// <param name="value">The object to serialize and encrypt</param>
    /// <param name="passes">Optional number of recursive encryption passes to run</param>
    /// <param name="key">Optional secret key with which to encrypt the value</param>
    /// <returns>The encrypted hash of <paramref name="value" /></returns>
    public static byte[] EncryptExternalRaw(object value, int? passes = null, string key = null)
    {
        // Make sure the key and passes are valid
        EnsureCryptographicRequirements(ref key, ref passes);

        // Convert the value to it's buffer-able byte array form
        byte[] buffer = Encoding.UTF8.GetBytes(value.ToString() ?? string.Empty);

        // Iterate to our pass
        for (int pass = 0; pass < passes; ++pass)
        {
            // Define our cryptographic service provider
            using SHA512CryptoServiceProvider provider = new SHA512CryptoServiceProvider();

            // Define our AES key
            byte[] aesKey = new byte[32];

            // Compute the cryptographic hash
            Buffer.BlockCopy(provider.ComputeHash(Encoding.UTF8.GetBytes(key)), 0, aesKey, 0, 32);

            // Generate our AES engine
            using Aes aes = Aes.Create();

            // Make sure we have a valid engine
            if (aes == null) throw new CryptographyException("Unable to instantiate AES Cryptographic Engine");

            // Set our key into the engine
            aes.Key = aesKey;

            // Create our encryption engine
            using ICryptoTransform transform = aes.CreateEncryptor(aes.Key, aes.IV);
            // Define our resulting stream
            using MemoryStream result = new MemoryStream();
            // Define our hash stream
            using CryptoStream aesStream = new CryptoStream(result, transform, CryptoStreamMode.Write);
            // Define our buffer stream
            using MemoryStream bufferStream = new MemoryStream(buffer);

            // Encrypt the plain text
            bufferStream.CopyTo(aesStream);

            // Define our resulting bytes
            byte[] resultingBytes = result.ToArray();
            // Define our combined result
            byte[] combinedBytes = new byte[aes.IV.Length + resultingBytes.Length];
            // Copy the initialization vector to the combined result
            Array.ConstrainedCopy(aes.IV, 0, combinedBytes, 0, aes.IV.Length);
            // Copy the hash to the combined result
            Array.ConstrainedCopy(resultingBytes, 0, combinedBytes, aes.IV.Length, resultingBytes.Length);
            // Reset the buffer byte array for the next pass
            buffer = combinedBytes;
        }

        // We're done, return the results
        return buffer;
    }

    /// <summary>
    /// This method asynchronously encrypts a value with no library identifiers in the hash
    /// </summary>
    /// <param name="value">The object to serialize and encrypt</param>
    /// <param name="passes">Optional number of recursive encryption passes to run</param>
    /// <param name="key">Optional secret key with which to encrypt the value</param>
    /// <returns>An awaitable task containing the encrypted hash of <paramref name="value" /></returns>
    public static async Task<byte[]> EncryptExternalRawAsync(object value, int? passes = null, string key = null)
    {
        // Make sure the key and passes are valid
        EnsureCryptographicRequirements(ref key, ref passes);

        // Convert the value to it's buffer-able byte array form
        byte[] buffer = Encoding.UTF8.GetBytes(value.ToString() ?? string.Empty);

        // Iterate to our pass
        for (int pass = 0; pass < passes; ++pass)
        {

            // Define our cryptographic service provider
            using SHA512CryptoServiceProvider provider = new SHA512CryptoServiceProvider();

            // Define our AES key
            byte[] aesKey = new byte[32];

            // Compute the cryptographic hash
            Buffer.BlockCopy(provider.ComputeHash(Encoding.UTF8.GetBytes(key)), 0, aesKey, 0, 32);

            // Generate our AES engine
            using Aes aes = Aes.Create();

            // Make sure we have a valid engine
            if (aes == null) throw new CryptographyException("Unable to instantiate AES Cryptographic Engine");

            // Set our key into the engine
            aes.Key = aesKey;

            // Create our encryption engine
            using ICryptoTransform transform = aes.CreateEncryptor(aes.Key, aes.IV);
            // Define our resulting stream
            await using MemoryStream result = new MemoryStream();
            // Define our hash stream
            await using CryptoStream aesStream = new CryptoStream(result, transform, CryptoStreamMode.Write);
            // Define our buffer stream
            await using MemoryStream bufferStream = new MemoryStream(buffer);

            // Encrypt the plain text
            await bufferStream.CopyToAsync(aesStream);

            // Define our resulting bytes
            byte[] resultingBytes = result.ToArray();
            // Define our combined result
            byte[] combinedBytes = new byte[aes.IV.Length + resultingBytes.Length];

            // Copy the initialization vector to the combined result
            Array.ConstrainedCopy(aes.IV, 0, combinedBytes, 0, aes.IV.Length);
            // Copy the hash to the combined result
            Array.ConstrainedCopy(resultingBytes, 0, combinedBytes, aes.IV.Length, resultingBytes.Length);

            // Reset the buffer byte array for the next pass
            buffer = combinedBytes;

        }

        // We're done, return the results
        return buffer;
    }

    /// <summary>
    /// This method generates the index for an encrypted value with index
    /// </summary>
    /// <param name="value">The value to generate the index from</param>
    /// <returns></returns>
    public static string GenerateIndex(object value)
    {
        // Localize our hash mechanism into a disposable context
        using SHA1 hashMechanism = SHA1.Create();

        // Ensure we have a value and return its base64 encoded value
        if (value?.ToString() is not null) return Convert.ToBase64String(Encoding.UTF8.GetBytes(value.ToString()));

        // We're done, no index to generate
        return null;
    }

    /// <summary>
    /// This method generates the index for an encrypted value of type <typeparamref name="TSource" /> with index
    /// </summary>
    /// <param name="value">The value to generate the index for</param>
    /// <param name="format">Optional serialization format for the data</param>
    /// <typeparam name="TSource">Type of <paramref name="value" /></typeparam>
    /// <returns>The hashed index of the value</returns>
    public static string GenerateIndex<TSource>(TSource value, SerializerFormat format = SerializerFormat.Json)
        where TSource : class, new() => GenerateIndex(format is SerializerFormat.Xml
        ? XmlSerializer.Serialize(value)
        : JsonSerializer.Serialize(value));

    /// <summary>
    /// This method returns the serialization format of the cryptographic hash
    /// </summary>
    /// <param name="hash">The cryptographic hash to test</param>
    /// <returns>The serialization format of the hash's value</returns>
    /// <exception cref="CryptographyException"></exception>
    public static SerializerFormat GetSerializationFormatFromHash(string hash)
    {
        // Ensure we have a valid serialized hash
        if (!IsSerializedValue(hash)) throw new CryptographyException("Invalid Hash:  Expected Complex, Got Simple");

        // We're done, send the format
        return Enum.Parse<SerializerFormat>(ValidateHash(hash, true).Groups[3].Value);
    }
    
    /// <summary>
    /// This method determines whether <paramref name="value" /> is a match for <paramref name="index" />
    /// </summary>
    /// <param name="value">The decrypted value to check</param>
    /// <param name="index">The index to compare against</param>
    /// <returns>A boolean denoting whether the index matches or not</returns>
    public static bool IndexMatches(dynamic value, string index) =>
        GenerateIndex(value).Equals(index);

    /// <summary>
    /// This method determines whether <paramref name="value" /> is a match for <paramref name="index" />
    /// </summary>
    /// <param name="value">The decrypted value to check</param>
    /// <param name="index">The index to compare against</param>
    /// <param name="format">Optional format with which to serialize the data</param>
    /// <typeparam name="TSource">The expected type of <paramref name="value" /></typeparam>
    /// <returns>A boolean denoting whether the index matches or not</returns>
    public static bool IndexMatches<TSource>(TSource value, string index, SerializerFormat format = SerializerFormat.Json) where TSource : class, new() =>
        GenerateIndex<TSource>(value, format).Equals(index);

    /// <summary>
    /// This method determines whether or not a cryptographic hash's value is a serialized complex type or not
    /// </summary>
    /// <param name="hash">The cryptographic hash to test</param>
    /// <returns>A boolean denoting whether the value is serialized or not</returns>
    public static bool IsSerializedValue(string hash) => ValidateHash(hash, true).Groups.Count is 4;

    /// <summary>
    /// This method determines whether or not an string represents a hash that this engine can work with
    /// </summary>
    /// <param name="value">The value to validate</param>
    /// <param name="throwException">Denotes whether to throw an exception or not</param>
    /// <returns>The RegEx match</returns>
    /// <exception cref="CryptographicException">When <paramref name="throwException"/> is <code>true</code> and the hash is NOT valid</exception>
    public static Match ValidateHash(string value, bool throwException)
    {
        // Localize the match
        Match match = Regex.Match(value, @"^{AES}\$([0-9]+)\$([0-9+]+)\$?(JSON|XML)?\$(.*)$",
            RegexOptions.IgnoreCase | RegexOptions.Multiline);
        // Make sure we have a match
        if (!match.Success && throwException) throw new CryptographicException("Invalid Hash");
        // We're done, return the match
        return match;
    }

    /// <summary>
    /// This method determines whether or not a string represents a hash that this engine can work with
    /// </summary>
    /// <param name="value">The value to validate</param>
    /// <returns>A boolean denoting validity</returns>
    public static bool ValidateHash(string value) => Regex.Match(value,
        @"^{AES}\$([0-9]+)\$([0-9+]+)\$?(JSON|XML)?\$(.*)$",
        RegexOptions.IgnoreCase | RegexOptions.Multiline).Success;
}
