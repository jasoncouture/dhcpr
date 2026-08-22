using System.Buffers;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Server.Orleans.Cache;

[GenerateSerializer]
public sealed class DnsCacheEventMessage
{
    [Id(0)]
    public DnsCacheEventKind Kind { get; set; }

    [Id(1)]
    public Guid OriginId { get; set; }

    [Id(2)]
    public byte[] RequestWire { get; set; } = [];

    [Id(3)]
    public byte[] ResponseWire { get; set; } = [];

    [Id(4)]
    public byte SecurityStatus { get; set; }

    [Id(5)]
    public DateTimeOffset CachedAt { get; set; }

    public static DnsCacheEventMessage Set(
        Guid originId,
        DomainMessage request,
        DomainMessage response,
        DnssecValidationStatus securityStatus,
        DateTimeOffset cachedAt)
        => new()
        {
            Kind = DnsCacheEventKind.Set,
            OriginId = originId,
            RequestWire = Encode(request),
            ResponseWire = Encode(response),
            SecurityStatus = (byte)securityStatus,
            CachedAt = cachedAt
        };

    public static DnsCacheEventMessage ForSecurityStatus(Guid originId, DomainMessage request, DnssecValidationStatus status)
        => new()
        {
            Kind = DnsCacheEventKind.UpdateSecurityStatus,
            OriginId = originId,
            RequestWire = Encode(request),
            SecurityStatus = (byte)status
        };

    public static DnsCacheEventMessage Clear(Guid originId)
        => new()
        {
            Kind = DnsCacheEventKind.Clear,
            OriginId = originId
        };

    public bool TryGetRequest(out DomainMessage request)
        => TryDecode(RequestWire, out request);

    public bool TryGetResponse(out DomainMessage response)
        => TryDecode(ResponseWire, out response);

    public DnssecValidationStatus GetSecurityStatus()
        => (DnssecValidationStatus)SecurityStatus;

    internal static byte[] Encode(DomainMessage message)
    {
        var rented = ArrayPool<byte>.Shared.Rent(Math.Max(65_535, message.EstimatedSize));
        try
        {
            var length = DomainMessageEncoder.Encode(rented, message);
            return rented.AsSpan(0, length).ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }

    private static bool TryDecode(byte[] wire, out DomainMessage message)
    {
        message = null!;
        if (wire is not { Length: > 0 })
            return false;

        try
        {
            message = DomainMessageEncoder.Decode(wire);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }
}
