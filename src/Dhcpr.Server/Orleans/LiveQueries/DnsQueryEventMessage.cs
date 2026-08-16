using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Server.Orleans.LiveQueries;

/// <summary>
/// Orleans-serializable live-query event. Endpoints are strings because <see cref="IPEndPoint"/> is not Orleans-friendly.
/// </summary>
[GenerateSerializer]
public sealed class DnsQueryEventMessage
{
    [Id(0)]
    public Guid Id { get; set; }

    [Id(1)]
    public DateTimeOffset Timestamp { get; set; }

    [Id(2)]
    public string? Client { get; set; }

    [Id(3)]
    public string? Server { get; set; }

    [Id(4)]
    public string Name { get; set; } = "";

    [Id(5)]
    public ushort Type { get; set; }

    [Id(6)]
    public byte ResponseCode { get; set; }

    [Id(7)]
    public bool CacheHit { get; set; }

    [Id(8)]
    public string Answers { get; set; } = "";

    [Id(9)]
    public string Middleware { get; set; } = "";

    public static DnsQueryEventMessage From(DnsQueryEvent evt) => new()
    {
        Id = evt.Id,
        Timestamp = evt.Timestamp,
        Client = evt.Client?.ToString(),
        Server = evt.Server?.ToString(),
        Name = evt.Name,
        Type = (ushort)evt.Type,
        ResponseCode = (byte)evt.ResponseCode,
        CacheHit = evt.CacheHit,
        Answers = evt.Answers,
        Middleware = evt.Middleware
    };

    public DnsQueryEvent ToDnsQueryEvent()
    {
        IPEndPoint? client = null;
        IPEndPoint? server = null;
        if (Client is not null && IPEndPoint.TryParse(Client, out var c))
            client = c;
        if (Server is not null && IPEndPoint.TryParse(Server, out var s))
            server = s;

        return new(
            Id,
            Timestamp,
            client,
            server,
            Name,
            (DomainRecordType)Type,
            (DomainResponseCode)ResponseCode,
            CacheHit,
            Answers,
            Middleware);
    }
}
