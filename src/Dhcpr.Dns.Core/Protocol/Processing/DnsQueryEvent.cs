using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed record DnsQueryEvent(
    Guid Id,
    DateTimeOffset Timestamp,
    IPEndPoint? Client,
    IPEndPoint? Server,
    string Name,
    DomainRecordType Type,
    DomainResponseCode ResponseCode,
    bool CacheHit,
    string Answers,
    string Middleware);
