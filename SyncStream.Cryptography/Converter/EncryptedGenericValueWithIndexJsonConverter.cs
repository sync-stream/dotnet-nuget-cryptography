using System.Text.Json;
using System.Text.Json.Serialization;
using SyncStream.Cryptography.Model;

// Define our namespace
namespace SyncStream.Cryptography.Converter;

/// <summary>
/// This class maintains our JSON converter for serializing and deserializing encrypted generic values 
/// </summary>
public class EncryptedGenericValueWithIndexJsonConverter<TSource> : JsonConverter<EncryptedValueWithIndex<TSource>>
    where TSource : class, new()
{
    /// <summary>
    /// This method reads the encrypted value from a JSON string
    /// </summary>
    /// <param name="reader">The reference instance of the JSON reader</param>
    /// <param name="typeToConvert">The type to be converted</param>
    /// <param name="options">The JSON serializer options</param>
    /// <returns>The deserialized typed value</returns>
    public override EncryptedValueWithIndex<TSource> Read(ref Utf8JsonReader reader, Type typeToConvert,
        JsonSerializerOptions options) => reader.GetString();

    /// <summary>
    /// This method writes an encrypted value to a JSON string
    /// </summary>
    /// <param name="writer">The JSON writer</param>
    /// <param name="value">The typed value to serialize</param>
    /// <param name="options">The JSON serializer options</param>
    public override void Write(Utf8JsonWriter writer, EncryptedValueWithIndex<TSource> value,
        JsonSerializerOptions options) => writer.WriteStringValue(value?.ToString());
}
