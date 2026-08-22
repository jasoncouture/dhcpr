using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Server.Orleans.Cache;

using Microsoft.Extensions.Caching.Memory;

namespace Dhcpr.Server.UnitTests;

public sealed class DnsCacheEventMessageTests
{
    [Fact]
    public void SetPayloadRoundTripsIntoReplicaCache()
    {
        var request = DomainMessage.CreateRequest("shared.example", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            new[]
            {
                new DomainResourceRecord(
                    request.Questions[0].Name,
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(180),
                    new IPAddressData(IPAddress.Parse("203.0.113.77")))
            },
            responseCode: DomainResponseCode.NoError);
        var cachedAt = DateTimeOffset.UtcNow;
        var origin = Guid.NewGuid();

        var evt = DnsCacheEventMessage.Set(origin, request, response, DnssecValidationStatus.Secure, cachedAt);

        Assert.Equal(DnsCacheEventKind.Set, evt.Kind);
        Assert.Equal(origin, evt.OriginId);
        Assert.True(evt.TryGetRequest(out var decodedRequest));
        Assert.True(evt.TryGetResponse(out var decodedResponse));
        Assert.Equal("shared.example", decodedRequest.Questions[0].Name.ToString());
        Assert.Equal(DomainRecordType.A, decodedRequest.Questions[0].Type);
        Assert.Equal(
            IPAddress.Parse("203.0.113.77"),
            ((IPAddressData)decodedResponse.Records.Answers[0].Data).Address);

        var replica = new DnsResponseCache(new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 }));
        replica.Import(decodedRequest, decodedResponse, evt.GetSecurityStatus(), evt.CachedAt);

        Assert.True(replica.TryGet(request, out var cached, out var status));
        Assert.Equal(DnssecValidationStatus.Secure, status);
        Assert.Equal(
            IPAddress.Parse("203.0.113.77"),
            ((IPAddressData)cached!.Records.Answers[0].Data).Address);
    }

    [Fact]
    public void ClearEventHasNoPayload()
    {
        var evt = DnsCacheEventMessage.Clear(Guid.NewGuid());
        Assert.Equal(DnsCacheEventKind.Clear, evt.Kind);
        Assert.Empty(evt.RequestWire);
        Assert.Empty(evt.ResponseWire);
    }
}
