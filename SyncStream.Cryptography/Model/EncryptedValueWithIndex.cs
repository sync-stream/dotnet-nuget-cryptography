using System.Text.Json.Serialization;
using System.Xml.Serialization;
using SyncStream.Cryptography.Converter;
using SyncStream.Serializer;

// Define our namespace
namespace SyncStream.Cryptography.Model;

/// <summary>
/// This class maintains the structure of an encrypted value with an index
/// </summary>
[JsonConverter(typeof(EncryptedValueWithIndexJsonConverter))]
[XmlInclude(typeof(EncryptedValue))]
[XmlRoot("encryptedValue")]
public class EncryptedValueWithIndex : EncryptedValue
{
    /// <summary>
    /// This property contains the cryptographic hash of the value
    /// </summary>
    [JsonPropertyName("hash")]
    [XmlText]
    public new string Hash { get => base.Hash; set => base.Hash = value; }
    
    /// <summary>
    /// This property contains the predictable index of the value
    /// </summary>
    [JsonPropertyName("index")]
    [XmlAttribute("index")]
    public string Index { get; set; }
    
    /// <summary>
    /// This method implicitly converts a <code>string</code> to an encrypted value
    /// </summary>
    /// <param name="valueOrHash">The plain-text value to encrypt or the cryptographic hash to decrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(string valueOrHash) => new(valueOrHash);

    /// <summary>
    /// This method implicitly converts a <code>bool</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(bool value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>bool?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(bool? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>decimal</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(decimal value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>decimal?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(decimal? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>double</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(double value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>double?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(double? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>float</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(float value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>float?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(float? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>int</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(int value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>int?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(int? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>long</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(long value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>long?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(long? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>DateTime</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(DateTime value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>DateTime?</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(DateTime? value) => new(value);

    /// <summary>
    /// This method implicitly converts a <code>Enum</code> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex(Enum value) => new(value);

    /// <summary>
    /// This method instantiates a new encrypted value
    /// </summary>
    public EncryptedValueWithIndex() { }

    /// <summary>
    /// This method instantiates our encrypted value with index from <paramref name="valueOrHash" />
    /// </summary>
    /// <param name="valueOrHash">The decrypted value or cryptographic hash with which to instantiate the instance</param>
    public EncryptedValueWithIndex(string valueOrHash) : base(valueOrHash)
    {
        // Generate the index
        Index = CryptographyService.GenerateIndex(Value);
    }

    /// <summary>
    /// This method instantiates our encrypted value with index from <paramref name="value" />
    /// </summary>
    /// <param name="value">The decrypted value with which to instantiate the instance</param>
    public EncryptedValueWithIndex(dynamic value) : base(value as object)
    {
        // Generate the index
        Index = CryptographyService.GenerateIndex(Value);
    }

    /// <summary>
    /// This method instantiates our encrypted value with index from <paramref name="hash" /> and <paramref name="value" />
    /// </summary>
    /// <param name="hash">The cryptographic hash of <paramref name="value" /> with which to instantiate the instance</param>
    /// <param name="value">The decrypted value with which to instantiate the instance</param>
    public EncryptedValueWithIndex(string hash, object value) : base(hash, value)
    {
        // Generate the index
        Index = CryptographyService.GenerateIndex(Value);
    }

    /// <summary>
    /// This method instantiates the instance from a <code>DateTime</code> <paramref name="value" />
    /// </summary>
    /// <param name="value">The value to be encrypted</param>
    public EncryptedValueWithIndex(DateTime value) : this(value.ToString("O")) { }

    /// <summary>
    /// This method instantiates the instance from a <code>DateTime?</code> <paramref name="value" />
    /// </summary>
    /// <param name="value">The value to be encrypted</param>
    public EncryptedValueWithIndex(DateTime? value) : this(value?.ToString("O")) { }

    /// <summary>
    /// This method instantiates the instance from a <code>Enum</code> <paramref name="value" />
    /// </summary>
    /// <param name="value">The value to be encrypted</param>
    public EncryptedValueWithIndex(Enum value) : this(value?.ToString()) { }

    /// <summary>
    /// This method determines whether a value matches the index or not
    /// </summary>
    /// <param name="value">The value to test</param>
    /// <returns>A boolean denoting whether <paramref name="value" /> matches the index or not</returns>
    public bool Matches(dynamic value) =>
        CryptographyService.IndexMatches(value, Hash);
}

/// <summary>
/// This class maintains the structure of an encrypted value of type <typeparamref name="TSource" /> with an index
/// </summary>
/// <typeparam name="TSource">The expected type of the value</typeparam>
[JsonConverter(typeof(EncryptedGenericValueWithIndexJsonConverterFactory))]
[XmlInclude(typeof(EncryptedValue))]
[XmlInclude(typeof(EncryptedValue<>))]
[XmlRoot("encryptedValue")]
public class EncryptedValueWithIndex<TSource> : EncryptedValue<TSource> where TSource: class, new()
{
    /// <summary>
    /// This property contains the cryptographic hash of the value
    /// </summary>
    [JsonPropertyName("hash")]
    [XmlText]
    public new string Hash { get => base.Hash; set => base.Hash = value; }
    
    /// <summary>
    /// This property contains the predictable index of the value
    /// </summary>
    [JsonPropertyName("index")]
    [XmlAttribute("index")]
    public string Index { get; set; }
    
    /// <summary>
    /// This method implicitly converts an encrypted hash string to an encrypted value
    /// </summary>
    /// <param name="hash">The hash to decrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex<TSource>(string hash) => new(hash);

    /// <summary>
    /// This method implicitly converts a <typeparamref name="TSource" /> to an encrypted value
    /// </summary>
    /// <param name="value">The value to encrypt</param>
    /// <returns></returns>
    public static implicit operator EncryptedValueWithIndex<TSource>(TSource value) => new(value);
    
    /// <summary>
    /// This method instantiates a new encrypted value
    /// </summary>
    public EncryptedValueWithIndex() { }

    /// <summary>
    /// This method instantiates our encrypted value with index from <paramref name="valueOrHash" />
    /// </summary>
    /// <param name="valueOrHash">The decrypted value or cryptographic hash with which to instantiate the instance</param>
    public EncryptedValueWithIndex(string valueOrHash) : base(valueOrHash)
    {
        // Generate the index
        Index = CryptographyService.GenerateIndex(Value, CryptographyService.GetSerializationFormatFromHash(Hash));
    }

    /// <summary>
    /// This method instantiates our encrypted value with index from <paramref name="hash" /> and <paramref name="value" />
    /// </summary>
    /// <param name="hash">The cryptographic hash of <paramref name="value" /> with which to instantiate the instance</param>
    /// <param name="value">The decrypted value with which to instantiate the instance</param>
    public EncryptedValueWithIndex(string hash, TSource value) : base(hash, value)
    {
        // Generate the index
        Index = CryptographyService.GenerateIndex<TSource>(value, CryptographyService.GetSerializationFormatFromHash(hash));
    }

    /// <summary>
    /// This method instantiates our encrypted value from <paramref name="value" /> of <typeparamref name="TSource" />
    /// </summary>
    /// <param name="value">The value to serialize and encrypt</param>
    /// <param name="format">Optional serialization format</param>
    public EncryptedValueWithIndex(TSource value, SerializerFormat format = SerializerFormat.Json) : base(
        CryptographyService.Encrypt<TSource>(value, format))
    {
        // Generate the index
        Index = CryptographyService.GenerateIndex<TSource>(value, format);
    }

    /// <summary>
    /// This method returns the decrypted value from the instance
    /// </summary>
    /// <returns>The decrypted value</returns>
    public new TSource GetValue() => Value;

    /// <summary>
    /// This method determines whether a value matches the index or not
    /// </summary>
    /// <param name="value">The value to test</param>
    /// <returns>A boolean denoting whether <paramref name="value" /> matches the index or not</returns>
    public bool Matches(TSource value) =>
        CryptographyService.IndexMatches<TSource>(value, Hash);
}
