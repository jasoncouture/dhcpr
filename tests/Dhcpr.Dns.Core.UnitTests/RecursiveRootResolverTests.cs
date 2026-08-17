using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;
using Dhcpr.Dns.Core.RootZone;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.UnitTests;

public class RecursiveRootResolverTests
{
    private static readonly IPEndPoint RootServer = new(IPAddress.Parse("198.41.0.4"), 53);
    private static readonly IPEndPoint ComServer = new(IPAddress.Parse("192.5.6.30"), 53);
    private static readonly IPEndPoint GoogleNs = new(IPAddress.Parse("216.239.32.10"), 53);
    private static readonly IPEndPoint AppleNs = new(IPAddress.Parse("17.253.200.1"), 53);
    private static readonly IPAddress GoogleWwwAddress = IPAddress.Parse("142.250.80.36");
    private static readonly IPAddress UnrelatedAddress = IPAddress.Parse("1.2.3.4");
    private static readonly IPAddress NsResolvedAddress = IPAddress.Parse("9.9.9.9");
    private static readonly IPAddress GslbAddress = IPAddress.Parse("17.253.201.8");

    [Fact]
    public async Task GoogleLikeNodataKeepsParentNameservers()
    {
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
            {
                return Referral("com", "a.gtld-servers.net", ComServer.Address);
            }

            if (type == DomainRecordType.NS && name.Equals("google.com", StringComparison.OrdinalIgnoreCase))
            {
                return Referral("google.com", "ns1.google.com", GoogleNs.Address);
            }

            // Leaf NS probe: authoritative NODATA with SOA only (no NS, no glue).
            if (type == DomainRecordType.NS && name.Equals("www.google.com", StringComparison.OrdinalIgnoreCase))
            {
                return NodataWithSoa("www.google.com");
            }

            if (type == DomainRecordType.A && name.Equals("www.google.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(GoogleNs.Address)))
                    return Answer(request, ARecord("www.google.com", GoogleWwwAddress));
                return EmptyNoError(request);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient);
        var request = DomainMessage.CreateRequest("www.google.com");
        var context = new DomainMessageContext(null, null, request);

        var result = await resolver.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(GoogleWwwAddress));
        Assert.DoesNotContain(internalClient.QueriedEndPoints, ep => ep.Address.Equals(GoogleWwwAddress));
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(GoogleNs.Address));
    }

    [Fact]
    public async Task ReferralUsesMatchingGlueOnly()
    {
        IPEndPoint? nextHopAfterCom = null;
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
            {
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(
                            NsRecord("com", "a.gtld-servers.net")),
                        ImmutableArray.Create(
                            ARecord("a.gtld-servers.net", ComServer.Address),
                            ARecord("unrelated.example", UnrelatedAddress))));
            }

            if (type == DomainRecordType.NS && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                return NodataWithSoa("example.com");
            }

            if (type == DomainRecordType.A && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(ComServer.Address)))
                    return Answer(request, ARecord("example.com", IPAddress.Parse("93.184.216.34")));
                return EmptyNoError(request);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) =>
        {
            queried.Add(endPoint);
            if (endPoint.Address.Equals(ComServer.Address))
                nextHopAfterCom = endPoint;
        });

        var resolver = CreateResolver(internalClient);
        var request = DomainMessage.CreateRequest("example.com");
        var result = await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(ComServer.Address));
        Assert.DoesNotContain(internalClient.QueriedEndPoints, ep => ep.Address.Equals(UnrelatedAddress));
        Assert.NotNull(nextHopAfterCom);
    }

    [Fact]
    public async Task ReferralWithoutGlueResolvesNsNamesInternally()
    {
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
            {
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(NsRecord("com", "a.gtld-servers.net")),
                        ImmutableArray<DomainResourceRecord>.Empty));
            }

            if (type == DomainRecordType.A && name.Equals("a.gtld-servers.net", StringComparison.OrdinalIgnoreCase))
            {
                return Answer(request, ARecord("a.gtld-servers.net", NsResolvedAddress));
            }

            if (type == DomainRecordType.AAAA && name.Equals("a.gtld-servers.net", StringComparison.OrdinalIgnoreCase))
            {
                return EmptyNoError(request);
            }

            if (type == DomainRecordType.NS && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                return NodataWithSoa("example.com");
            }

            if (type == DomainRecordType.A && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(NsResolvedAddress)))
                    return Answer(request, ARecord("example.com", IPAddress.Parse("93.184.216.34")));
                return EmptyNoError(request);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient);
        var request = DomainMessage.CreateRequest("example.com");
        var result = await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(NsResolvedAddress));
        Assert.Contains(internalClient.Queries,
            q => q.Equals("a.gtld-servers.net/A", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task NsAddressResolveIgnoresAdditionalAForOtherOwners()
    {
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
            {
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(NsRecord("com", "a.gtld-servers.net")),
                        ImmutableArray<DomainResourceRecord>.Empty));
            }

            if (type == DomainRecordType.A && name.Equals("a.gtld-servers.net", StringComparison.OrdinalIgnoreCase))
            {
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(authoritative: true),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray.Create(ARecord("a.gtld-servers.net", NsResolvedAddress)),
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(ARecord("cdn.example.net", UnrelatedAddress))));
            }

            if (type == DomainRecordType.AAAA && name.Equals("a.gtld-servers.net", StringComparison.OrdinalIgnoreCase))
                return EmptyNoError(request);

            if (type == DomainRecordType.NS && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
                return NodataWithSoa("example.com");

            if (type == DomainRecordType.A && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(NsResolvedAddress)))
                    return Answer(request, ARecord("example.com", IPAddress.Parse("93.184.216.34")));
                return EmptyNoError(request);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient);
        var request = DomainMessage.CreateRequest("example.com");
        await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.DoesNotContain(internalClient.QueriedEndPoints, ep => ep.Address.Equals(UnrelatedAddress));
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(NsResolvedAddress));
    }

    [Fact]
    public async Task DoesNotFollowNonNoErrorAsReferral()
    {
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
                return Referral("com", "a.gtld-servers.net", ComServer.Address);

            if (type == DomainRecordType.NS && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
                return NodataWithSoa("example.com");

            if (type == DomainRecordType.A && name.Equals("noexist.example.com", StringComparison.OrdinalIgnoreCase))
            {
                return new DomainMessage(
                    request.Id,
                    new DomainMessageFlags(
                        true, DomainOperationCode.Query, true, false, false, false, false, false,
                        DomainResponseCode.NameError),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(
                            SoaRecord("example.com"),
                            NsRecord("example.com", "evil.example.net")),
                        ImmutableArray.Create(ARecord("evil.example.net", UnrelatedAddress))));
            }

            return EmptyNoError(request);
        });

        var resolver = CreateResolver(internalClient);
        var request = DomainMessage.CreateRequest("noexist.example.com");
        var result = await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NameError, result!.Flags.ResponseCode);
        Assert.DoesNotContain(internalClient.QueriedEndPoints, ep => ep.Address.Equals(UnrelatedAddress));
    }

    [Fact]
    public async Task UnrelatedAddressInAdditionalIsNotUsedAsNameserver()
    {
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
            {
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(NsRecord("com", "a.gtld-servers.net")),
                        ImmutableArray.Create(
                            ARecord("cdn.example.net", UnrelatedAddress),
                            ARecord("a.gtld-servers.net", ComServer.Address))));
            }

            if (type == DomainRecordType.NS &&
                (name.Equals("facebook.com", StringComparison.OrdinalIgnoreCase) ||
                 name.Equals("www.facebook.com", StringComparison.OrdinalIgnoreCase)))
            {
                return NodataWithSoa(name);
            }

            if (type == DomainRecordType.A && name.Equals("www.facebook.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(ComServer.Address)))
                    return Answer(request, ARecord("www.facebook.com", IPAddress.Parse("157.240.3.35")));
                return EmptyNoError(request);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient);
        var request = DomainMessage.CreateRequest("www.facebook.com");
        await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.DoesNotContain(internalClient.QueriedEndPoints, ep => ep.Address.Equals(UnrelatedAddress));
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(ComServer.Address));
    }

    [Fact]
    public async Task TwoLabelNameQueriesZoneNsThenAnswers()
    {
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
                return Referral("com", "a.gtld-servers.net", ComServer.Address);

            if (type == DomainRecordType.NS && name.Equals("google.com", StringComparison.OrdinalIgnoreCase))
                return Referral("google.com", "ns1.google.com", GoogleNs.Address);

            if (type == DomainRecordType.A && name.Equals("google.com", StringComparison.OrdinalIgnoreCase))
            {
                // TLD would only refer; authoritative NS answers.
                if (queried.Any(ep => ep.Address.Equals(GoogleNs.Address)))
                    return Answer(request, ARecord("google.com", GoogleWwwAddress));
                return Referral("google.com", "ns1.google.com", GoogleNs.Address);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient);
        var request = DomainMessage.CreateRequest("google.com");
        var result = await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(GoogleWwwAddress));
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(GoogleNs.Address));
    }

    [Fact]
    public async Task SecondLookupReusesCachedComNs()
    {
        // Caching of upstream NS queries is owned by CacheResolverDecorator on the pipeline.
        // This unit tests the resolver in isolation; simulate cache by memoizing NS/com responses.
        var comNsQueries = 0;
        var queried = new List<IPEndPoint>();
        var comNsResponse = Referral("com", "a.gtld-servers.net", ComServer.Address);
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
            {
                Interlocked.Increment(ref comNsQueries);
                return comNsResponse;
            }

            if (type == DomainRecordType.NS && name.Equals("google.com", StringComparison.OrdinalIgnoreCase))
                return Referral("google.com", "ns1.google.com", GoogleNs.Address);

            if (type == DomainRecordType.NS && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
                return NodataWithSoa("example.com");

            if (type == DomainRecordType.A && name.Equals("www.google.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(GoogleNs.Address)))
                    return Answer(request, ARecord("www.google.com", GoogleWwwAddress));
                return EmptyNoError(request);
            }

            if (type == DomainRecordType.A && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(ComServer.Address)))
                    return Answer(request, ARecord("example.com", IPAddress.Parse("93.184.216.34")));
                return EmptyNoError(request);
            }

            if (type == DomainRecordType.NS &&
                name.Equals("www.google.com", StringComparison.OrdinalIgnoreCase))
                return NodataWithSoa(name);

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint), cacheUpstreamNs: true);

        var resolver = CreateResolver(internalClient);
        await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("www.google.com")),
            CancellationToken.None);
        Assert.Equal(1, comNsQueries);

        await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com")),
            CancellationToken.None);
        Assert.Equal(1, comNsQueries);
    }

    [Fact]
    public async Task CnameTargetAuthorityNsIsNotTreatedAsZoneCut()
    {
        // apple.com NS answer itunes.apple.com/NS with a CNAME plus NS for the
        // CNAME target (v.aaplimg.com). Those GSLB servers REFUSE bag.itunes;
        // the parent still has the CNAME. Do not switch nameservers.
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
                return Referral("com", "a.gtld-servers.net", ComServer.Address);

            if (type == DomainRecordType.NS && name.Equals("apple.com", StringComparison.OrdinalIgnoreCase))
                return Referral("apple.com", "a.ns.apple.com", AppleNs.Address);

            if (type == DomainRecordType.NS &&
                name.Equals("itunes.apple.com", StringComparison.OrdinalIgnoreCase))
            {
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(authoritative: true),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray.Create(
                            CnameRecord("itunes.apple.com", "itunes-cdn-itunes-apple-com.v.aaplimg.com")),
                        ImmutableArray.Create(
                            NsRecord("v.aaplimg.com", "a.gslb.aaplimg.com"),
                            NsRecord("v.aaplimg.com", "b.gslb.aaplimg.com")),
                        ImmutableArray.Create(
                            ARecord("a.gslb.aaplimg.com", GslbAddress),
                            ARecord("b.gslb.aaplimg.com", GslbAddress))));
            }

            if (type == DomainRecordType.A &&
                name.Equals("bag.itunes.apple.com", StringComparison.OrdinalIgnoreCase))
            {
                return Answer(
                    request,
                    CnameRecord("bag.itunes.apple.com", "bag-cdn.itunes-apple.com.akadns.net"));
            }

            return EmptyNoError(request);
        });

        var resolver = CreateResolver(internalClient);
        var result = await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("bag.itunes.apple.com")),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.CNAME &&
            ((NameData)r.Data).Name.ToString()
                .Equals("bag-cdn.itunes-apple.com.akadns.net", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(AppleNs.Address));
        Assert.DoesNotContain(internalClient.QueriedEndPoints, ep => ep.Address.Equals(GslbAddress));
    }

    [Fact]
    public async Task NsQueryFollowsToChildAndPutsNsInAnswers()
    {
        // TLD referral has parent NS + NSEC3. Child returns the apex NS in ANSWER.
        // Do not copy the parent referral into ANSWER.
        var vultrNs = IPAddress.Parse("108.61.10.10");
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
                return Referral("com", "a.gtld-servers.net", ComServer.Address);

            if (type == DomainRecordType.NS &&
                name.Equals("instigaterevolution.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(vultrNs)))
                {
                    return Answer(
                        request,
                        NsRecord("instigaterevolution.com", "ns1.vultr.com"),
                        NsRecord("instigaterevolution.com", "ns2.vultr.com"));
                }

                return ParentNsReferralWithNsec3("instigaterevolution.com", "ns1.vultr.com", vultrNs);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient);
        var result = await resolver.ProcessAsync(
            new DomainMessageContext(
                null,
                null,
                DomainMessage.CreateRequest("instigaterevolution.com", DomainRecordType.NS)),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.False(result.Flags.Authoritative);
        Assert.Equal(2, result.Records.Answers.Count(r => r.Type == DomainRecordType.NS));
        Assert.DoesNotContain(result.Records.Authorities, r => r.Type == DomainRecordType.NS);
        Assert.DoesNotContain(result.Records.Authorities, r => r.Type is DomainRecordType.NSEC3);
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(vultrNs));
    }

    [Fact]
    public async Task SignedNsQueryUsesChildRrsetNotParentReferral()
    {
        var googleNs = IPAddress.Parse("216.239.32.10");
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
                return Referral("com", "a.gtld-servers.net", ComServer.Address);

            if (type == DomainRecordType.NS && name.Equals("google.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(googleNs)))
                {
                    return Answer(
                        request,
                        NsRecord("google.com", "ns1.google.com"),
                        NsRecord("google.com", "ns2.google.com"),
                        FakeNsRrsig("google.com"));
                }

                // .com puts delegation NS in ANSWER without AA and without the
                // child's RRSIG. That must not finish the lookup.
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray.Create(NsRecord("google.com", "ns1.google.com")),
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(ARecord("ns1.google.com", googleNs))));
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient);
        var result = await resolver.ProcessAsync(
            new DomainMessageContext(
                null,
                null,
                DomainMessage.CreateRequest("google.com", DomainRecordType.NS)),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.False(result.Flags.Authoritative);
        Assert.Contains(result.Records.Answers, r => r.Type == DomainRecordType.NS);
        Assert.Contains(result.Records.Answers, r => r.Type == DomainRecordType.RRSIG);
        Assert.DoesNotContain(result.Records.Authorities, r => r.Type == DomainRecordType.NS);
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(googleNs));
    }

    [Fact]
    public async Task SoaQueryFollowsToChildAnswer()
    {
        var exampleNs = IPAddress.Parse("192.0.2.53");
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
                return Referral("com", "a.gtld-servers.net", ComServer.Address);

            if (type == DomainRecordType.NS && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
                return Referral("example.com", "ns1.example.com", exampleNs);

            if (type == DomainRecordType.SOA && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(exampleNs)))
                    return Answer(request, SoaRecord("example.com"));
                return Referral("example.com", "ns1.example.com", exampleNs);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient);
        var result = await resolver.ProcessAsync(
            new DomainMessageContext(
                null,
                null,
                DomainMessage.CreateRequest("example.com", DomainRecordType.SOA)),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Contains(result.Records.Answers, r => r.Type == DomainRecordType.SOA);
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(exampleNs));
    }

    [Fact]
    public async Task NsQueryForNonApexDoesNotLoopOnParentNsInAuthority()
    {
        var exampleNs = IPAddress.Parse("192.0.2.53");
        var hops = 0;
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
                return Referral("com", "a.gtld-servers.net", ComServer.Address);

            if (type == DomainRecordType.NS && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
                return Referral("example.com", "ns1.example.com", exampleNs);

            if (type == DomainRecordType.NS &&
                name.Equals("www.example.com", StringComparison.OrdinalIgnoreCase))
            {
                Interlocked.Increment(ref hops);
                var nodata = NodataWithSoa("www.example.com");
                return nodata with
                {
                    Records = nodata.Records with
                    {
                        Authorities = nodata.Records.Authorities.Add(
                            NsRecord("example.com", "ns1.example.com")),
                        Additional = ImmutableArray.Create(ARecord("ns1.example.com", exampleNs))
                    }
                };
            }

            return EmptyNoError(request);
        });

        var resolver = CreateResolver(internalClient);
        var result = await resolver.ProcessAsync(
            new DomainMessageContext(
                null,
                null,
                DomainMessage.CreateRequest("www.example.com", DomainRecordType.NS)),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Empty(result.Records.Answers);
        Assert.True(hops <= 2, $"self-referral looped {hops} times");
    }

    [Fact]
    public async Task UpstreamDirectedContextIsIgnored()
    {
        var internalClient = new ScriptedInternalDomainClient(_ =>
            throw new InvalidOperationException("should not query"));
        var resolver = CreateResolver(internalClient);
        var request = DomainMessage.CreateRequest("example.com");
        var context = new DomainMessageContext(null, null, request)
        {
            UpstreamEndpoints = ImmutableArray.Create(RootServer)
        };

        var result = await resolver.ProcessAsync(context, CancellationToken.None);

        Assert.Null(result);
    }

    private static RecursiveRootResolver CreateResolver(IInternalDomainClient internalClient)
    {
        var tips = new RootServerTips(new TestOptionsMonitor(new RootServerConfiguration
        {
            Addresses = new[] { RootServer.ToString() }
        }));

        return new RecursiveRootResolver(
            tips,
            internalClient,
            NullLogger<RecursiveRootResolver>.Instance);
    }

    private static DomainMessage Referral(string zone, string nsName, IPAddress glue)
        => new(
            1,
            ResponseFlags(),
            ImmutableArray.Create(new DomainQuestion(new DomainLabels(zone), DomainRecordType.NS, DomainRecordClass.IN)),
            new DomainResourceRecords(
                ImmutableArray<DomainResourceRecord>.Empty,
                ImmutableArray.Create(NsRecord(zone, nsName)),
                ImmutableArray.Create(ARecord(nsName, glue))));

    private static DomainMessage NodataWithSoa(string name)
        => new(
            1,
            ResponseFlags(authoritative: true),
            ImmutableArray.Create(new DomainQuestion(new DomainLabels(name), DomainRecordType.NS, DomainRecordClass.IN)),
            new DomainResourceRecords(
                ImmutableArray<DomainResourceRecord>.Empty,
                ImmutableArray.Create(new DomainResourceRecord(
                    new DomainLabels(name),
                    DomainRecordType.SOA,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new StartOfAuthorityData(
                        new DomainLabels("ns1.example.com"),
                        new DomainLabels("hostmaster.example.com"),
                        1, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60),
                        TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60)))),
                ImmutableArray<DomainResourceRecord>.Empty));

    private static DomainMessage Answer(DomainMessage request, params DomainResourceRecord[] answers)
    {
        var response = DomainMessage.CreateResponse(request, answers, responseCode: DomainResponseCode.NoError);
        return response with { Flags = response.Flags with { Authoritative = true } };
    }

    private static DomainMessage EmptyNoError(DomainMessage request)
        => DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.NoError);

    private static DomainMessageFlags ResponseFlags(bool authoritative = false)
        => new(true, DomainOperationCode.Query, authoritative, false, false, false, false, false,
            DomainResponseCode.NoError);

    private static DomainResourceRecord NsRecord(string owner, string target)
        => new(new DomainLabels(owner), DomainRecordType.NS, DomainRecordClass.IN, TimeSpan.FromSeconds(60),
            new NameData(new DomainLabels(target)));

    private static DomainResourceRecord CnameRecord(string owner, string target)
        => new(new DomainLabels(owner), DomainRecordType.CNAME, DomainRecordClass.IN, TimeSpan.FromSeconds(60),
            new NameData(new DomainLabels(target)));

    private static DomainResourceRecord SoaRecord(string owner)
        => new(new DomainLabels(owner), DomainRecordType.SOA, DomainRecordClass.IN, TimeSpan.FromSeconds(60),
            new StartOfAuthorityData(
                new DomainLabels("ns1.example.com"),
                new DomainLabels("hostmaster.example.com"),
                1, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60),
                TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60)));

    private static DomainResourceRecord FakeNsRrsig(string owner)
        => new(new DomainLabels(owner), DomainRecordType.RRSIG, DomainRecordClass.IN, TimeSpan.FromSeconds(60),
            new ResourceRecordSignatureData(
                DomainRecordType.NS,
                DnssecAlgorithmType.EcdsaP256Sha256,
                2,
                60,
                1,
                0,
                12345,
                new DomainLabels(owner),
                ImmutableArray.Create<byte>(1, 2, 3, 4)));

    private static DomainMessage ParentNsReferralWithNsec3(string zone, string nsName, IPAddress glue)
        => new(
            1,
            ResponseFlags(),
            ImmutableArray.Create(new DomainQuestion(new DomainLabels(zone), DomainRecordType.NS, DomainRecordClass.IN)),
            new DomainResourceRecords(
                ImmutableArray.Create(NsRecord(zone, nsName)),
                ImmutableArray.Create(
                    new DomainResourceRecord(
                        new DomainLabels("CK0POJMG874LJREF7EFN8430QVIT8BSM.com"),
                        DomainRecordType.NSEC3,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(900),
                        new NextSecure3Data(
                            Nsec3HashAlgorithm.Sha1,
                            1,
                            0,
                            ImmutableArray<byte>.Empty,
                            ImmutableArray.Create<byte>(1, 2, 3),
                            ImmutableArray<byte>.Empty))),
                ImmutableArray.Create(ARecord(nsName, glue))));

    private static DomainResourceRecord ARecord(string owner, IPAddress address)
        => new(new DomainLabels(owner), DomainRecordType.A, DomainRecordClass.IN, TimeSpan.FromSeconds(60),
            new IPAddressData(address));

    private sealed class TestOptionsMonitor : IOptionsMonitor<RootServerConfiguration>
    {
        public TestOptionsMonitor(RootServerConfiguration current) => CurrentValue = current;
        public RootServerConfiguration CurrentValue { get; }
        public RootServerConfiguration Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<RootServerConfiguration, string?> listener) => null;
    }

    /// <summary>
    /// Stands in for the middleware pipeline: upstream endpoints simulate UpstreamQueryMiddleware.
    /// Glue A/AAAA are directed at the current nameserver set (same as production).
    /// </summary>
    private sealed class ScriptedInternalDomainClient : IInternalDomainClient
    {
        private readonly Func<DomainMessage, DomainMessage> _script;
        private readonly Action<DomainMessage, IPEndPoint>? _onUpstreamQuery;
        private readonly bool _cacheUpstreamNs;
        private readonly Dictionary<string, DomainMessage> _nsCache = new(StringComparer.OrdinalIgnoreCase);

        public ScriptedInternalDomainClient(
            Func<DomainMessage, DomainMessage> script,
            Action<DomainMessage, IPEndPoint>? onUpstreamQuery = null,
            bool cacheUpstreamNs = false)
        {
            _script = script;
            _onUpstreamQuery = onUpstreamQuery;
            _cacheUpstreamNs = cacheUpstreamNs;
        }

        public List<IPEndPoint> QueriedEndPoints { get; } = new();
        public List<string> Queries { get; } = new();

        public ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
            => SendAsync(
                new DomainMessageContext(null, null, message) { IsInternal = true },
                message,
                upstreamEndpoints: default,
                cancellationToken);

        public ValueTask<DomainMessage> SendAsync(
            DomainMessageContext parentContext,
            DomainMessage message,
            CancellationToken cancellationToken)
            => SendAsync(parentContext, message, upstreamEndpoints: default, cancellationToken);

        public ValueTask<DomainMessage> SendAsync(
            DomainMessageContext parentContext,
            DomainMessage message,
            ImmutableArray<IPEndPoint> upstreamEndpoints,
            CancellationToken cancellationToken)
        {
            Queries.Add($"{message.Questions[0].Name}/{message.Questions[0].Type}");

            if (upstreamEndpoints.IsDefaultOrEmpty)
                return ValueTask.FromResult(Handle(message));

            foreach (var endPoint in upstreamEndpoints)
            {
                QueriedEndPoints.Add(endPoint);
                _onUpstreamQuery?.Invoke(message, endPoint);
            }

            if (_cacheUpstreamNs && message.Questions[0].Type == DomainRecordType.NS)
            {
                var key = message.Questions[0].Name.ToString();
                if (_nsCache.TryGetValue(key, out var cached))
                    return ValueTask.FromResult(cached with { Id = message.Id });

                var response = Handle(message);
                _nsCache[key] = response;
                return ValueTask.FromResult(response);
            }

            return ValueTask.FromResult(Handle(message));
        }

        private DomainMessage Handle(DomainMessage request)
        {
            var response = _script(request);
            return response with { Id = request.Id };
        }
    }
}
