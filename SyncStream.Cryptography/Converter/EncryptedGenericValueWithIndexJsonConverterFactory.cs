using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using SyncStream.Cryptography.Model;

// Define our namespace
namespace SyncStream.Cryptography.Converter;

/// <summary>
/// This class maintains the JSON converter for our generic encrypted values
/// </summary>
public class EncryptedGenericValueWithIndexJsonConverterFactory : JsonConverterFactory
{
    /// <summary>
    /// This method determines whether or not this converter can convert the value's type
    /// </summary>
    /// <param name="typeToConvert">The value type in question</param>
    /// <returns>A boolean denoting whether this converter can work with the value or not</returns>
    public override bool CanConvert(Type typeToConvert)
    {
        // Ensure we're working with a generic type
        if (!typeToConvert.IsGenericType) return false;

        // We're done, ensure the proper generic type and return
        return typeToConvert.GetGenericTypeDefinition() == typeof(EncryptedValue<>);
    }

    /// <summary>
    /// This method generates a converter for our type
    /// </summary>
    /// <param name="typeToConvert">The type to generate a converter for</param>
    /// <param name="options">The JSON serializer options</param>
    /// <returns>The JSON converter for the type</returns>
    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options) =>
        (JsonConverter) Activator.CreateInstance(
            type: typeof(EncryptedValueWithIndex<>).MakeGenericType(new Type[]
                {typeToConvert.GetGenericArguments()[0]}), BindingFlags.Instance | BindingFlags.Public, binder: null,
            args: new object[] {options}, culture: null)!;
}
