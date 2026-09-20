using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;
using Dhcpr.Dns.Core.RootZone;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class RecursiveRootResolverTests
{
    private static readonly IPEndPoint _rootServer = new(IPAddress.Parse("198.41.0.4"), 53);
    private static readonly IPEndPoint _comServer = new(IPAddress.Parse("192.5.6.30"), 53);
    private static readonly IPEndPoint _googleNs = new(IPAddress.Parse("216.239.32.10"), 53);
    private static readonly IPEndPoint _appleNs = new(IPAddress.Parse("17.253.200.1"), 53);
    private static readonly IPAddress _googleWwwAddress = IPAddress.Parse("142.250.80.36");
    private static readonly IPAddress _unrelatedAddress = IPAddress.Parse("1.2.3.4");
    private static readonly IPAddress _nsResolvedAddress = IPAddress.Parse("9.9.9.9");
    private static readonly IPAddress _gslbAddress = IPAddress.Parse("17.253.201.8");

    [Fact]
    public async Task GoogleLikeNodataKeepsParentNameservers()
    {
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.A && name.Equals("www.google.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(_googleNs.Address)))
                    return Answer(request, ARecord("www.google.com", _googleWwwAddress));
                if (queried.Any(ep => ep.Address.Equals(_comServer.Address)))
                    return Referral("google.com", "ns1.google.com", _googleNs.Address);
                return Referral("com", "a.gtld-servers.net", _comServer.Address);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient.Client);
        var request = DomainMessage.CreateRequest("www.google.com");
        var context = new DomainMessageContext(null, null, request);

        var result = await resolver.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(_googleWwwAddress));
        Assert.DoesNotContain(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_googleWwwAddress));
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_googleNs.Address));
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

            if (type == DomainRecordType.A && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(_comServer.Address)))
                    return Answer(request, ARecord("example.com", IPAddress.Parse("93.184.216.34")));
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(
                            NsRecord("com", "a.gtld-servers.net")),
                        ImmutableArray.Create(
                            ARecord("a.gtld-servers.net", _comServer.Address),
                            ARecord("unrelated.example", _unrelatedAddress))));
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) =>
        {
            queried.Add(endPoint);
            if (endPoint.Address.Equals(_comServer.Address))
                nextHopAfterCom = endPoint;
        });

        var resolver = CreateResolver(internalClient.Client);
        var request = DomainMessage.CreateRequest("example.com");
        var result = await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_comServer.Address));
        Assert.DoesNotContain(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_unrelatedAddress));
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

            if (type == DomainRecordType.A && name.Equals("a.gtld-servers.net", StringComparison.OrdinalIgnoreCase))
            {
                return Answer(request, ARecord("a.gtld-servers.net", _nsResolvedAddress));
            }

            if (type == DomainRecordType.AAAA && name.Equals("a.gtld-servers.net", StringComparison.OrdinalIgnoreCase))
            {
                return EmptyNoError(request);
            }

            if (type == DomainRecordType.A && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(_nsResolvedAddress)))
                    return Answer(request, ARecord("example.com", IPAddress.Parse("93.184.216.34")));
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(NsRecord("com", "a.gtld-servers.net")),
                        ImmutableArray<DomainResourceRecord>.Empty));
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient.Client);
        var request = DomainMessage.CreateRequest("example.com");
        var result = await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_nsResolvedAddress));
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

            if (type == DomainRecordType.A && name.Equals("a.gtld-servers.net", StringComparison.OrdinalIgnoreCase))
            {
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(authoritative: true),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray.Create(ARecord("a.gtld-servers.net", _nsResolvedAddress)),
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(ARecord("cdn.example.net", _unrelatedAddress))));
            }

            if (type == DomainRecordType.AAAA && name.Equals("a.gtld-servers.net", StringComparison.OrdinalIgnoreCase))
                return EmptyNoError(request);

            if (type == DomainRecordType.A && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(_nsResolvedAddress)))
                    return Answer(request, ARecord("example.com", IPAddress.Parse("93.184.216.34")));
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(NsRecord("com", "a.gtld-servers.net")),
                        ImmutableArray<DomainResourceRecord>.Empty));
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient.Client);
        var request = DomainMessage.CreateRequest("example.com");
        await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.DoesNotContain(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_unrelatedAddress));
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_nsResolvedAddress));
    }

    [Fact]
    public async Task DoesNotFollowNonNoErrorAsReferral()
    {
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.A && name.Equals("noexist.example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (!queried.Any(ep => ep.Address.Equals(_comServer.Address)))
                    return Referral("com", "a.gtld-servers.net", _comServer.Address);

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
                        ImmutableArray.Create(ARecord("evil.example.net", _unrelatedAddress))));
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient.Client);
        var request = DomainMessage.CreateRequest("noexist.example.com");
        var result = await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NameError, result!.Flags.ResponseCode);
        Assert.DoesNotContain(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_unrelatedAddress));
    }

    [Fact]
    public async Task UnrelatedAddressInAdditionalIsNotUsedAsNameserver()
    {
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.A && name.Equals("www.facebook.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(_comServer.Address)))
                    return Answer(request, ARecord("www.facebook.com", IPAddress.Parse("157.240.3.35")));
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(NsRecord("com", "a.gtld-servers.net")),
                        ImmutableArray.Create(
                            ARecord("cdn.example.net", _unrelatedAddress),
                            ARecord("a.gtld-servers.net", _comServer.Address))));
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient.Client);
        var request = DomainMessage.CreateRequest("www.facebook.com");
        await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.DoesNotContain(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_unrelatedAddress));
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_comServer.Address));
    }

    [Fact]
    public async Task TwoLabelNameQueriesZoneNsThenAnswers()
    {
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.A && name.Equals("google.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(_googleNs.Address)))
                    return Answer(request, ARecord("google.com", _googleWwwAddress));
                if (queried.Any(ep => ep.Address.Equals(_comServer.Address)))
                    return Referral("google.com", "ns1.google.com", _googleNs.Address);
                return Referral("com", "a.gtld-servers.net", _comServer.Address);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient.Client);
        var request = DomainMessage.CreateRequest("google.com");
        var result = await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(_googleWwwAddress));
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_googleNs.Address));
    }

    [Fact]
    public async Task SharedTipCacheSkipsKnownZoneCut()
    {
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.A && name.Equals("www.google.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(_googleNs.Address)))
                    return Answer(request, ARecord("www.google.com", _googleWwwAddress));
                if (queried.Any(ep => ep.Address.Equals(_comServer.Address)))
                    return Referral("google.com", "ns1.google.com", _googleNs.Address);
                return Referral("com", "a.gtld-servers.net", _comServer.Address);
            }

            if (type == DomainRecordType.A && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(_comServer.Address)))
                    return Answer(request, ARecord("example.com", IPAddress.Parse("93.184.216.34")));
                return Referral("com", "a.gtld-servers.net", _comServer.Address);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var tips = new NameserverTipCache();
        var resolver = CreateResolver(internalClient.Client);
        await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("www.google.com"))
            {
                NameserverTips = tips
            },
            CancellationToken.None);
        var rootAfterFirst = queried.Count(ep => ep.Address.Equals(_rootServer.Address));
        Assert.True(rootAfterFirst > 0);

        await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com"))
            {
                NameserverTips = tips
            },
            CancellationToken.None);
        Assert.Equal(rootAfterFirst, queried.Count(ep => ep.Address.Equals(_rootServer.Address)));
    }

    [Fact]
    public async Task DsForRememberedZoneStartsAtRootNotChild()
    {
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.A && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(_comServer.Address)))
                    return Answer(request, ARecord("example.com", IPAddress.Parse("93.184.216.34")));
                return Referral("com", "a.gtld-servers.net", _comServer.Address);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var tips = new NameserverTipCache();
        var resolver = CreateResolver(internalClient.Client);
        await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com"))
            {
                NameserverTips = tips
            },
            CancellationToken.None);

        var before = internalClient.QueriedEndPoints.Count;
        await resolver.ProcessAsync(
            new DomainMessageContext(
                null,
                null,
                DomainMessage.CreateRequest("com", DomainRecordType.DS))
            {
                NameserverTips = tips
            },
            CancellationToken.None);

        var dsHops = internalClient.QueriedEndPoints.Skip(before).ToList();
        Assert.Contains(dsHops, ep => ep.Address.Equals(_rootServer.Address));
        Assert.DoesNotContain(dsHops, ep => ep.Address.Equals(_comServer.Address));
    }

    [Fact]
    public async Task CnameTargetAuthorityNsIsNotTreatedAsZoneCut()
    {
        // apple.com NS answer bag.itunes with a CNAME plus NS for the
        // CNAME target (v.aaplimg.com). Those GSLB servers REFUSE bag.itunes;
        // the parent still has the CNAME. Do not switch nameservers.
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.A &&
                name.Equals("bag.itunes.apple.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(_appleNs.Address)))
                {
                    return new DomainMessage(
                        request.Id,
                        ResponseFlags(authoritative: true),
                        request.Questions,
                        new DomainResourceRecords(
                            ImmutableArray.Create(
                                CnameRecord("bag.itunes.apple.com", "bag-cdn.itunes-apple.com.akadns.net")),
                            ImmutableArray.Create(
                                NsRecord("v.aaplimg.com", "a.gslb.aaplimg.com"),
                                NsRecord("v.aaplimg.com", "b.gslb.aaplimg.com")),
                            ImmutableArray.Create(
                                ARecord("a.gslb.aaplimg.com", _gslbAddress),
                                ARecord("b.gslb.aaplimg.com", _gslbAddress))));
                }

                if (queried.Any(ep => ep.Address.Equals(_comServer.Address)))
                    return Referral("apple.com", "a.ns.apple.com", _appleNs.Address);
                return Referral("com", "a.gtld-servers.net", _comServer.Address);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient.Client);
        var result = await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("bag.itunes.apple.com")),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.CNAME &&
            ((NameData)r.Data).Name.ToString()
                .Equals("bag-cdn.itunes-apple.com.akadns.net", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_appleNs.Address));
        Assert.DoesNotContain(internalClient.QueriedEndPoints, ep => ep.Address.Equals(_gslbAddress));
    }

    [Fact]
    public async Task EmptyNonTerminalNxDomainDoesNotAbortZoneWalk()
    {
        // Netflix-style empty non-terminals: the parent is delegated, but
        // intermediate labels (internal.dradis… / us-east-2.internal.dradis…)
        // are AA NXDOMAIN while the leaf still exists.
        var dradisNs = IPAddress.Parse("192.0.2.80");
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.A &&
                name.Equals("ichnaea-web.us-east-2.internal.dradis.netflix.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(dradisNs)))
                {
                    return Answer(
                        request,
                        CnameRecord(
                            "ichnaea-web.us-east-2.internal.dradis.netflix.com",
                            "apiproxy-log-nlb.elb.us-east-2.amazonaws.com"));
                }

                var netflixNs = IPAddress.Parse("205.251.192.101");
                if (queried.Any(ep => ep.Address.Equals(netflixNs)))
                    return Referral("dradis.netflix.com", "e.ns.nflxso.net", dradisNs);
                if (queried.Any(ep => ep.Address.Equals(_comServer.Address)))
                    return Referral("netflix.com", "ns-101.awsdns-12.com", netflixNs);
                return Referral("com", "a.gtld-servers.net", _comServer.Address);
            }

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient.Client);
        var result = await resolver.ProcessAsync(
            new DomainMessageContext(
                null,
                null,
                DomainMessage.CreateRequest(
                    "ichnaea-web.us-east-2.internal.dradis.netflix.com")),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.CNAME &&
            ((NameData)r.Data).Name.ToString()
                .Equals("apiproxy-log-nlb.elb.us-east-2.amazonaws.com", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(internalClient.QueriedEndPoints, ep => ep.Address.Equals(dradisNs));
        Assert.DoesNotContain(internalClient.Queries,
            q => q.Equals("us-east-2.internal.dradis.netflix.com/NS", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task CnameFallbackKeepsOriginalQuestionType()
    {
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.A && name.Equals("alias.example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (queried.Any(ep => ep.Address.Equals(_comServer.Address)))
                    return EmptyNoError(request);
                return Referral("com", "a.gtld-servers.net", _comServer.Address);
            }

            if (type == DomainRecordType.CNAME && name.Equals("alias.example.com", StringComparison.OrdinalIgnoreCase))
                return Answer(request, CnameRecord("alias.example.com", "target.example.com"));

            return EmptyNoError(request);
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient.Client);
        var request = DomainMessage.CreateRequest("alias.example.com");
        var result = await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainRecordType.A, result!.Questions[0].Type);
        Assert.Contains(result.Records.Answers, r => r.Type == DomainRecordType.CNAME);
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
                return Referral("com", "a.gtld-servers.net", _comServer.Address);

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

        var resolver = CreateResolver(internalClient.Client);
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
                return Referral("com", "a.gtld-servers.net", _comServer.Address);

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

        var resolver = CreateResolver(internalClient.Client);
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
                return Referral("com", "a.gtld-servers.net", _comServer.Address);

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

        var resolver = CreateResolver(internalClient.Client);
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
        var queried = new List<IPEndPoint>();
        var internalClient = new ScriptedInternalDomainClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS &&
                name.Equals("www.example.com", StringComparison.OrdinalIgnoreCase))
            {
                if (!queried.Any(ep => ep.Address.Equals(_comServer.Address)))
                    return Referral("com", "a.gtld-servers.net", _comServer.Address);
                if (!queried.Any(ep => ep.Address.Equals(exampleNs)))
                    return Referral("example.com", "ns1.example.com", exampleNs);

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
        }, onUpstreamQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(internalClient.Client);
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
    public async Task UpstreamDirectedContextCallsInner()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var request = DomainMessage.CreateRequest("example.com");
        var passed = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(passed);

        var tips = new RootServerTips(Monitor(new RootServerConfiguration
        {
            Addresses = new[] { _rootServer.ToString() }
        }));
        var resolver = new RecursiveRootResolver(
            inner,
            tips,
            new ReferralWalker(new ScriptedInternalDomainClient(_ =>
                throw new InvalidOperationException("should not query")).Client),
            NullLogger<RecursiveRootResolver>.Instance);
        var context = new DomainMessageContext(null, null, request)
        {
            UpstreamEndpoints = ImmutableArray.Create(_rootServer)
        };

        var result = await resolver.ProcessAsync(context, CancellationToken.None);

        Assert.Same(passed, result);
        await inner.Received(1)
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    private static RecursiveRootResolver CreateResolver(IInternalDomainClient internalClient)
    {
        var tips = new RootServerTips(Monitor(new RootServerConfiguration
        {
            Addresses = new[] { _rootServer.ToString() }
        }));

        return new RecursiveRootResolver(
            PassThroughInner(),
            tips,
            new ReferralWalker(internalClient),
            NullLogger<RecursiveRootResolver>.Instance);
    }

    private static IDomainMessageMiddleware PassThroughInner()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(call => DomainMessage.CreateResponse(
                call.Arg<DomainMessageContext>().DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.ServerFailure));
        return inner;
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

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }

    /// <summary>
    /// Stands in for the middleware pipeline: upstream endpoints simulate UpstreamQueryMiddleware.
    /// Glue A/AAAA are directed at the current nameserver set (same as production).
    /// </summary>
    private sealed class ScriptedInternalDomainClient
    {
        public IInternalDomainClient Client { get; }
        public List<IPEndPoint> QueriedEndPoints { get; } = [];
        public List<string> Queries { get; } = [];

        public ScriptedInternalDomainClient(
            Func<DomainMessage, DomainMessage> script,
            Action<DomainMessage, IPEndPoint>? onUpstreamQuery = null,
            bool cacheUpstreamNs = false)
        {
            var nsCache = new Dictionary<string, DomainMessage>(StringComparer.OrdinalIgnoreCase);
            var client = Substitute.For<IInternalDomainClient>();

            ValueTask<DomainMessage> Send(DomainMessage message, ImmutableArray<IPEndPoint> upstreamEndpoints)
            {
                Queries.Add($"{message.Questions[0].Name}/{message.Questions[0].Type}");

                if (upstreamEndpoints.IsDefaultOrEmpty)
                    return ValueTask.FromResult(Handle(message));

                foreach (var endPoint in upstreamEndpoints)
                {
                    QueriedEndPoints.Add(endPoint);
                    onUpstreamQuery?.Invoke(message, endPoint);
                }

                if (cacheUpstreamNs && message.Questions[0].Type == DomainRecordType.NS)
                {
                    var key = message.Questions[0].Name.ToString();
                    if (nsCache.TryGetValue(key, out var cached))
                        return ValueTask.FromResult(cached with { Id = message.Id });

                    var response = Handle(message);
                    nsCache[key] = response;
                    return ValueTask.FromResult(response);
                }

                return ValueTask.FromResult(Handle(message));
            }

            DomainMessage Handle(DomainMessage request) => script.Invoke(request) with { Id = request.Id };

            client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
                .Returns(ci => Send(ci.Arg<DomainMessage>(), default));
            client.SendAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
                .Returns(ci => Send(ci.ArgAt<DomainMessage>(1), default));
            client.SendAsync(
                    Arg.Any<DomainMessageContext>(),
                    Arg.Any<DomainMessage>(),
                    Arg.Any<ImmutableArray<IPEndPoint>>(),
                    Arg.Any<CancellationToken>())
                .Returns(ci => Send(ci.ArgAt<DomainMessage>(1), ci.ArgAt<ImmutableArray<IPEndPoint>>(2)));

            Client = client;
        }
    }
}
