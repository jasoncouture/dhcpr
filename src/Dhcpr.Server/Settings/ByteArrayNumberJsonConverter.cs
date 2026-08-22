using System.Text.Json;
using System.Text.Json.Serialization;

namespace Dhcpr.Server.Settings;

internal sealed class ByteArrayNumberJsonConverter : JsonConverter<byte[]>
{
    public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Null)
            return [];
        if (reader.TokenType != JsonTokenType.StartArray)
            throw new JsonException("Expected a JSON array of bytes.");

        var values = new List<byte>();
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndArray)
                return values.ToArray();
            values.Add(reader.GetByte());
        }

        throw new JsonException("Unterminated byte array.");
    }

    public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options)
    {
        writer.WriteStartArray();
        foreach (var item in value)
            writer.WriteNumberValue(item);
        writer.WriteEndArray();
    }
}
