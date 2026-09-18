using System.Text.Json.Serialization;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server.Orleans.LiveQueries;

namespace Dhcpr.Server.LiveQueries;

internal sealed record LiveQueryWebSocketMessage(
    Guid Id,
    DateTimeOffset Timestamp,
    string? Client,
    string? Server,
    string Name,
    string Type,
    string ResponseCode,
    bool CacheHit,
    string Answers,
    string Middleware,
    string Source)
{
    public static LiveQueryWebSocketMessage From(DnsQueryEventMessage evt) => new(
        evt.Id,
        evt.Timestamp,
        evt.Client,
        evt.Server,
        evt.Name,
        ((DomainRecordType)evt.Type).ToString(),
        ((DomainResponseCode)evt.ResponseCode).ToString(),
        evt.CacheHit,
        evt.Answers,
        evt.Middleware,
        ((DnsQuerySource)evt.Source).ToLabel());
}

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(LiveQueryWebSocketMessage))]
internal sealed partial class LiveQueryWebSocketJsonContext : JsonSerializerContext;
