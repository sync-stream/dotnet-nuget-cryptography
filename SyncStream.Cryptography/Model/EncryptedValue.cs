using System.Text.Json.Serialization;
using System.Xml.Serialization;
using SyncStream.Cryptography.Converter;
using SyncStream.Serializer;

// Define our namespace
namespace SyncStream.Cryptography.Model;

/// <summary>
/// This class maintains the structure of an encrypted value
/// </summary>
[JsonConverter(typeof(EncryptedValueJsonConverter))]
[XmlRoot("encryptedValue")]
public class EncryptedValue
{
    /// <summary>
    /// This property contains the internal decrypted value
    /// </summary>
    protected dynamic Value;

    /// <summary>
    /// This property contains the cryptographic hash of the value
    /// </summary>
    [XmlText]
    [JsonIgnore]
    public string Hash { get; protected set; }

    /// <summary>
    /// This method implicitly converts a <code>string</code> to an encrypted value
    /// </summary>
    /// <param name="valueOrHash">The plain-text value to encrypt or the cryptographic hash to decrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(string valueOrHash) => new(valueOrHash);

    /// <summary>
    /// This method implicitly converts a <code>bool</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(bool value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>bool?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(bool? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>decimal</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(decimal value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>decimal?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(decimal? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>double</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(double value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>double?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(double? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>float</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(float value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>float?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(float? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>int</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(int value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>int?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(int? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>long</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(long value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>long?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(long? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>DateTime</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(DateTime value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>DateTime?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(DateTime? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>Enum</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue(Enum value) => new(value);
    
    /// <summary>
    /// This method instantiates an empty encrypted value
    /// </summary>
    public EncryptedValue() { }

    /// <summary>
    /// This method instantiates our encrypted value from a string containing a hash or value
    /// </summary>
    /// <param name="valueOrHash">The encrypted hash or plain-text string with which to populate the instance</param>
    public EncryptedValue(string valueOrHash)
    {
        // Check for a valid hash
        if (CryptographyService.ValidateHash(valueOrHash))
            ValueFromHash<string>(valueOrHash);
        else
            HashFromValue(valueOrHash);
    }
    
    /// <summary>
    /// This method instantiates the encrypted value with a <paramref name="hash" /> and <paramref name="value" />
    /// </summary>
    /// <param name="hash">The cryptographic hash representing <paramref name="value" /></param>
    /// <param name="value">The value that is encrypted</param>
    public EncryptedValue(string hash, dynamic value)
    {
        // Set the hash into the instance
        Hash = hash;
        // Set the value into the instance
        Value = value;
    }

    /// <summary>
    /// This method instantiates the instance from <paramref name="value" />
    /// </summary>
    /// <param name="value">The value to be encrypted</param>
    public EncryptedValue(dynamic value) => HashFromValue(value?.ToString());

    /// <summary>
    /// This method instantiates the instance from a <code>DateTime</code> <paramref name="value" />
    /// </summary>
    /// <param name="value">The value to be encrypted</param>
    public EncryptedValue(DateTime value) => HashFromValue(value.ToString("O"));

    /// <summary>
    /// This method instantiates the instance from a <code>DateTime?</code> <paramref name="value" />
    /// </summary>
    /// <param name="value">The value to be encrypted</param>
    public EncryptedValue(DateTime? value) => HashFromValue(value?.ToString("O"));

    /// <summary>
    /// This method instantiates the instance from a <code>Enum</code> <paramref name="value" />
    /// </summary>
    /// <param name="value">The value to be encrypted</param>
    public EncryptedValue(Enum value) => HashFromValue(value?.ToString());

    /// <summary>
    /// This method asynchronously encrypts <paramref name="value" /> and returns the hash
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns>The encrypted hash of <paramref name="value" /></returns>
    protected void HashFromValue(dynamic value)
    {
        // Set the hash into the instance
        Hash = CryptographyService.Encrypt(value?.ToString());
        // Set the value into the instance
        Value = value;
    }

    /// <summary>
    /// This method asynchronously encrypts <paramref name="value" /> and returns the hash
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns>An awaitable task containing the encrypted hash of <paramref name="value" /></returns>
    protected async Task HashFromValueAsync(dynamic value)
    {
        // Set the hash into the instance
        Hash = await CryptographyService.EncryptAsync(value?.ToString());
        // Set the value into the instance
        Value = value;
    }

    /// <summary>
    /// This method decrypts <paramref name="hash" /> into <typeparamref name="TTarget" /> and returns it
    /// </summary>
    /// <param name="hash">The hash to decrypt</param>
    /// <typeparam name="TTarget">The type to return the value as</typeparam>
    /// <returns>The decrypted <paramref name="hash"/> of <typeparamref name="TTarget"/></returns>
    protected void ValueFromHash<TTarget>(string hash)
    {
        // Set the hash into the instance
        Hash = hash;
        // Set the value into the instance
        Value = Convert.ChangeType(CryptographyService.Decrypt(hash), typeof(TTarget));
    }

    /// <summary>
    /// This method asynchronously decrypts <paramref name="hash" /> into <typeparamref name="TTarget" /> and returns it
    /// </summary>
    /// <param name="hash">The hash to decrypt</param>
    /// <typeparam name="TTarget">The type to return the value as</typeparam>
    /// <returns>An awaitable task containing the decrypted <paramref name="hash"/> of <typeparamref name="TTarget"/></returns>
    protected async Task ValueFromHashAsync<TTarget>(string hash)
    {
        // Set the hash into the instance
        Hash = hash;
        // Set the value into the instance
        Value = Convert.ChangeType(await CryptographyService.DecryptAsync(hash), typeof(TTarget));
    }

    /// <summary>
    /// This method returns the generic value from the instance
    /// </summary>
    /// <returns>The decrypted generic value</returns>
    public dynamic GetValue() => Value;

    /// <summary>
    /// This method returns the <typeparamref name="TTarget" /> value from the instance
    /// </summary>
    /// <typeparam name="TTarget">The expected type of the value</typeparam>
    /// <returns>The decrypted <typeparamref name="TTarget" /> value</returns>
    public TTarget GetValue<TTarget>() => (TTarget) Value;

    /// <summary>
    /// This method converts the instance to a string
    /// </summary>
    /// <returns>The encrypted hash from the instance</returns>
    public override string ToString() => Hash;
}

/// <summary>
/// This class maintains the structure of an encrypted <typeparamref name="TSource" /> value 
/// </summary>
/// <typeparam name="TSource">The encrypted value's type</typeparam>
[JsonConverter(typeof(EncryptedGenericValueJsonConverterFactory))]
[XmlInclude(typeof(EncryptedValue))]
[XmlRoot("encryptedValue")]
public class EncryptedValue<TSource> : EncryptedValue where TSource : class, new()
{
    /// <summary>
    /// This property contains the internal decrypted value
    /// </summary>
    protected new TSource Value => base.Value as TSource;

    /// <summary>
    /// This method implicitly converts an encrypted hash string to an encrypted value
    /// </summary>
    /// <param name="hash">The hash to decrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue<TSource>(string hash) => new(hash);

    /// <summary>
    /// This method implicitly converts a <typeparamref name="TSource" /> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValue<TSource>(TSource value) => new(value);
    
    /// <summary>
    /// This method instantiates a new encrypted value
    /// </summary>
    public EncryptedValue() { }

    /// <summary>
    /// This method instantiates our encrypted value from <paramref name="hash" />
    /// </summary>
    /// <param name="hash">The cryptographic hash</param>
    public EncryptedValue(string hash) : base(hash) { }
    
    /// <summary>
    /// This method instantiates our encrypted value from <paramref name="hash" /> and <paramref name="value" />
    /// </summary>
    /// <param name="hash">The cryptographic hash of <paramref name="value" /></param>
    /// <param name="value">The decrypted value</param>
    public EncryptedValue(string hash, TSource value) : base(hash, value) { }

    /// <summary>
    /// This method instantiates our encrypted value from <paramref name="value" /> of <typeparamref name="TSource" />
    /// </summary>
    /// <param name="value">The value to serialize and encrypt</param>
    /// <param name="format">Optional serialization format</param>
    public EncryptedValue(TSource value, SerializerFormat format = SerializerFormat.Json) : base(
        CryptographyService.Encrypt<TSource>(value, format)) { }

    /// <summary>
    /// This method returns the decrypted value from the instance
    /// </summary>
    /// <returns>The decrypted value</returns>
    public new TSource GetValue() => Value;
}
