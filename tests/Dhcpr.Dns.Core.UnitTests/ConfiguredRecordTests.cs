using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.ConfiguredRecords;
using Dhcpr.Dns.Core.DynamicDns;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class ConfiguredRecordTests
{
    [Fact]
    public void ExactAAndAaaa()
    {
        var index = Index(
            Rec("www.home.arpa", "A", "10.0.0.5"),
            Rec("www.home.arpa", "AAAA", "2001:db8::5"));

        var a = Answer(index, "www.home.arpa", DomainRecordType.A);
        Assert.NotNull(a);
        Assert.True(a!.Flags.Authoritative);
        Assert.Contains(a.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("10.0.0.5")));

        var aaaa = Answer(index, "www.home.arpa", DomainRecordType.AAAA);
        Assert.NotNull(aaaa);
        Assert.Contains(aaaa!.Records.Answers, r =>
            r.Type == DomainRecordType.AAAA &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("2001:db8::5")));
    }

    [Fact]
    public void CnameFallbackForOtherTypes()
    {
        var index = Index(Rec("alias.home.arpa", "CNAME", "www.home.arpa"));

        var result = Answer(index, "alias.home.arpa", DomainRecordType.A);
        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r =>
            r.Type == DomainRecordType.CNAME &&
            ((NameData)r.Data).Name.ToString() == "www.home.arpa");
    }

    [Fact]
    public void ExactNsIncludesGlue()
    {
        var index = Index(
            Rec("sub.home.arpa", "NS", "ns1.home.arpa"),
            Rec("ns1.home.arpa", "A", "192.0.2.1"),
            Rec("ns1.home.arpa", "AAAA", "2001:db8::1"));

        var result = Answer(index, "sub.home.arpa", DomainRecordType.NS);
        Assert.NotNull(result);
        Assert.True(result!.Flags.Authoritative);
        Assert.Contains(result.Records.Answers, r => r.Type == DomainRecordType.NS);
        Assert.Contains(result.Records.Additional, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("192.0.2.1")));
        Assert.Contains(result.Records.Additional, r => r.Type == DomainRecordType.AAAA);
    }

    [Fact]
    public void WildcardSynthesizesQname()
    {
        var index = Index(Rec("*.apps.home.arpa", "A", "10.0.0.99"));

        var result = Answer(index, "foo.apps.home.arpa", DomainRecordType.A);
        Assert.NotNull(result);
        var answer = Assert.Single(result!.Records.Answers);
        Assert.Equal("foo.apps.home.arpa", answer.Name.ToString());
        Assert.Equal(IPAddress.Parse("10.0.0.99"), ((IPAddressData)answer.Data).Address);
    }

    [Fact]
    public void WildcardCnameSynthesizesQname()
    {
        var index = Index(Rec("*.apps.home.arpa", "CNAME", "ingress.home.arpa"));

        var result = Answer(index, "foo.apps.home.arpa", DomainRecordType.A);
        Assert.NotNull(result);
        var answer = Assert.Single(result!.Records.Answers);
        Assert.Equal(DomainRecordType.CNAME, answer.Type);
        Assert.Equal("foo.apps.home.arpa", answer.Name.ToString());
        Assert.Equal("ingress.home.arpa", ((NameData)answer.Data).Name.ToString());
    }

    [Fact]
    public void WildcardMatchesMultiLabelWhenCloserNodesMissing()
    {
        var index = Index(Rec("*.apps.home.arpa", "A", "10.0.0.99"));

        var result = Answer(index, "a.b.apps.home.arpa", DomainRecordType.A);
        Assert.NotNull(result);
        Assert.Equal("a.b.apps.home.arpa", Assert.Single(result!.Records.Answers).Name.ToString());
    }

    [Fact]
    public void ExactNameSuppressesParentWildcard()
    {
        var index = Index(
            Rec("foo.home.arpa", "A", "10.0.0.1"),
            Rec("*.home.arpa", "A", "10.0.0.99"));

        var exact = Answer(index, "foo.home.arpa", DomainRecordType.A);
        Assert.Equal(IPAddress.Parse("10.0.0.1"), Address(exact));

        var wild = Answer(index, "bar.home.arpa", DomainRecordType.A);
        Assert.Equal(IPAddress.Parse("10.0.0.99"), Address(wild));

        Assert.Null(Answer(index, "a.foo.home.arpa", DomainRecordType.A));
    }

    [Fact]
    public void NamesBelowNsCutAreReferralsNotWildcards()
    {
        var index = Index(
            Rec("sub.home.arpa", "NS", "ns1.elsewhere.com"),
            Rec("*.home.arpa", "A", "10.0.0.99"));

        var result = Answer(index, "foo.sub.home.arpa", DomainRecordType.A);
        Assert.NotNull(result);
        Assert.False(result!.Flags.Authoritative);
        Assert.Empty(result.Records.Answers);
        Assert.Contains(result.Records.Authorities, r => r.Type == DomainRecordType.NS);
    }

    [Fact]
    public void EmptyClientsMatchesAnyIncludingUnknown()
    {
        var index = Index(Rec("www.home.arpa", "A", "10.0.0.5"));

        Assert.NotNull(Answer(index, "www.home.arpa", DomainRecordType.A, client: null));
        Assert.NotNull(Answer(index, "www.home.arpa", DomainRecordType.A, IPAddress.Parse("1.2.3.4")));
    }

    [Fact]
    public void RestrictedWinsOverUnrestrictedForSameType()
    {
        var index = Index(
            Rec("www.home.arpa", "A", "10.0.0.5", clients: ["10.0.0.0/8"]),
            Rec("www.home.arpa", "A", "203.0.113.10"));

        Assert.Equal(
            IPAddress.Parse("10.0.0.5"),
            Address(Answer(index, "www.home.arpa", DomainRecordType.A, IPAddress.Parse("10.1.2.3"))));
        Assert.Equal(
            IPAddress.Parse("203.0.113.10"),
            Address(Answer(index, "www.home.arpa", DomainRecordType.A, IPAddress.Parse("1.2.3.4"))));
        Assert.Equal(
            IPAddress.Parse("203.0.113.10"),
            Address(Answer(index, "www.home.arpa", DomainRecordType.A, client: null)));
    }

    [Fact]
    public void NonMatchingSubnetFallsThrough()
    {
        var index = Index(Rec("www.home.arpa", "A", "10.0.0.5", clients: ["10.0.0.0/8"]));

        Assert.Null(Answer(index, "www.home.arpa", DomainRecordType.A, IPAddress.Parse("1.2.3.4")));
        Assert.Null(Answer(index, "www.home.arpa", DomainRecordType.A, client: null));
    }

    [Fact]
    public void Ipv4MappedClientMatchesIpv4Cidr()
    {
        var index = Index(Rec("www.home.arpa", "A", "10.0.0.5", clients: ["10.0.0.0/8"]));
        var mapped = IPAddress.Parse("10.1.2.3").MapToIPv6();

        Assert.Equal(
            IPAddress.Parse("10.0.0.5"),
            Address(Answer(index, "www.home.arpa", DomainRecordType.A, mapped)));
    }

    [Fact]
    public void MissFallsThrough()
    {
        var index = Index(Rec("www.home.arpa", "A", "10.0.0.5"));
        Assert.Null(Answer(index, "other.home.arpa", DomainRecordType.A));
    }

    [Fact]
    public void ExactOwnerWrongTypeIsNodata()
    {
        var index = Index(Rec("www.home.arpa", "A", "10.0.0.5"));
        var result = Answer(index, "www.home.arpa", DomainRecordType.AAAA);
        Assert.NotNull(result);
        Assert.Empty(result!.Records.Answers);
        Assert.Equal(DomainResponseCode.NoError, result.Flags.ResponseCode);
    }

    [Fact]
    public void WildcardWrongTypeIsNodata()
    {
        var index = Index(Rec("*.apps.home.arpa", "A", "10.0.0.99"));
        var result = Answer(index, "foo.apps.home.arpa", DomainRecordType.AAAA);
        Assert.NotNull(result);
        Assert.Empty(result!.Records.Answers);
        Assert.Equal(DomainResponseCode.NoError, result.Flags.ResponseCode);
    }

    [Fact]
    public void DefaultTtlIs300()
    {
        var index = Index(Rec("www.home.arpa", "A", "10.0.0.5"));
        var result = Answer(index, "www.home.arpa", DomainRecordType.A);
        Assert.Equal(TimeSpan.FromSeconds(300), Assert.Single(result!.Records.Answers).TimeToLive);
    }

    [Fact]
    public void ValidationRejectsUnsupportedTypeAndMidNameWildcard()
    {
        Assert.False(Valid(out var mxError, Rec("www.home.arpa", "MX", "10.0.0.5")));
        Assert.Contains("A, AAAA, CNAME, or NS", mxError);

        Assert.False(Valid(out var wildError, Rec("foo.*.home.arpa", "A", "10.0.0.5")));
        Assert.Contains("leftmost", wildError);
    }

    [Fact]
    public void ValidationRejectsCnameSharingClientsWithAnotherType()
    {
        Assert.False(Valid(
            out var error,
            Rec("www.home.arpa", "CNAME", "other.home.arpa"),
            Rec("www.home.arpa", "A", "10.0.0.5")));
        Assert.Contains("CNAME", error);
        Assert.Contains("Clients", error);
    }

    [Fact]
    public void ValidationRejectsBadValueClientsAndTtl()
    {
        Assert.False(Valid(out var ipv4, Rec("www.home.arpa", "A", "2001:db8::1")));
        Assert.Contains("IPv4", ipv4);

        Assert.False(Valid(out var cidr, Rec("www.home.arpa", "A", "10.0.0.5", clients: ["not-a-net"])));
        Assert.Contains("Clients", cidr);

        Assert.False(Valid(out var ttl, Rec("www.home.arpa", "A", "10.0.0.5", ttl: 0)));
        Assert.Contains("Ttl", ttl);
    }

    [Fact]
    public async Task MiddlewareSetsDoNotCacheAndSkipsDirectedHops()
    {
        var middleware = CreateMiddleware(ValidConfig(Rec("www.home.arpa", "A", "10.0.0.5")));
        var request = DomainMessage.CreateRequest("www.home.arpa");
        var context = new DomainMessageContext(null, null, request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.True(context.DoNotCacheResponse);
        Assert.Equal(ConfiguredRecordMiddleware.MiddlewarePriority, middleware.Priority);
        Assert.True(middleware.Priority < 200);

        var directed = new DomainMessageContext(null, null, request)
        {
            UpstreamEndpoints = ImmutableArray.Create(new IPEndPoint(IPAddress.Parse("1.1.1.1"), 53))
        };
        Assert.Null(await middleware.ProcessAsync(directed, CancellationToken.None));
    }

    [Fact]
    public async Task MiddlewareReadsCurrentValueOnEachQuery()
    {
        var initial = ValidConfig(Rec("www.home.arpa", "A", "10.0.0.5"));
        var empty = ValidConfig();
        var monitor = Substitute.For<IOptionsMonitor<DnsConfiguration>>();
        monitor.CurrentValue.Returns(initial);

        var middleware = new ConfiguredRecordMiddleware(PassThroughInner(), monitor);
        var hit = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("www.home.arpa")),
            CancellationToken.None);
        Assert.NotNull(hit);

        monitor.CurrentValue.Returns(empty);
        var miss = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("www.home.arpa")),
            CancellationToken.None);
        Assert.Null(miss);
    }

    [Fact]
    public async Task ConfigOwnerShadowsDynDnsIncludingOtherTypes()
    {
        var dyn = DynamicDnsTestHelpers.CreateStore();
        dyn.Upsert("www.home.arpa", IPAddress.Parse("203.0.113.50"), IPAddress.Parse("2001:db8::50"));
        var dynMiddleware = new DynamicDnsMiddleware(dyn, new AuthoritativeZoneStore());
        var configMiddleware = CreateMiddleware(ValidConfig(Rec("www.home.arpa", "A", "10.0.0.5")));

        var aContext = new DomainMessageContext(null, null, DomainMessage.CreateRequest("www.home.arpa"));
        var a = await configMiddleware.ProcessAsync(aContext, CancellationToken.None);
        Assert.NotNull(a);
        Assert.Equal(IPAddress.Parse("10.0.0.5"), Address(a));

        var aaaaContext = new DomainMessageContext(
            null,
            null,
            DomainMessage.CreateRequest("www.home.arpa", DomainRecordType.AAAA));
        var aaaa = await configMiddleware.ProcessAsync(aaaaContext, CancellationToken.None);
        Assert.NotNull(aaaa);
        Assert.Empty(aaaa!.Records.Answers);

        var dynStillThere = await dynMiddleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("www.home.arpa")),
            CancellationToken.None);
        Assert.NotNull(dynStillThere);
        Assert.Equal(IPAddress.Parse("203.0.113.50"), Address(dynStillThere));
    }

    [Fact]
    public async Task MissStillReachesDynDns()
    {
        var dyn = DynamicDnsTestHelpers.CreateStore();
        dyn.Upsert("dyn.home.arpa", IPAddress.Parse("203.0.113.60"), ipv6: null);
        var dynMiddleware = new DynamicDnsMiddleware(dyn, new AuthoritativeZoneStore());
        var configMiddleware = CreateMiddleware(ValidConfig(Rec("www.home.arpa", "A", "10.0.0.5")));

        var request = DomainMessage.CreateRequest("dyn.home.arpa");
        var context = new DomainMessageContext(null, null, request);
        Assert.Null(await configMiddleware.ProcessAsync(context, CancellationToken.None));

        var dynAnswer = await dynMiddleware.ProcessAsync(context, CancellationToken.None);
        Assert.Equal(IPAddress.Parse("203.0.113.60"), Address(dynAnswer));
    }

    private static IPAddress Address(DomainMessage? message)
    {
        Assert.NotNull(message);
        var answer = Assert.Single(message!.Records.Answers);
        return ((IPAddressData)answer.Data).Address;
    }

    private static DomainMessage? Answer(
        ParsedConfiguredRecordIndex index,
        string qname,
        DomainRecordType type,
        IPAddress? client = null)
        => index.TryAnswer(DomainMessage.CreateRequest(qname, type), client);

    private static ParsedConfiguredRecordIndex Index(params DnsRecordConfiguration[] records)
    {
        Assert.True(ParsedConfiguredRecordIndex.TryBuild(records, out var index, out var error), error);
        return index!;
    }

    private static DnsRecordConfiguration Rec(
        string name,
        string type,
        string value,
        int? ttl = null,
        string[]? clients = null)
        => new()
        {
            Name = name,
            Type = type,
            Ttl = ttl,
            Value = value,
            Clients = clients ?? []
        };

    private static bool Valid(out string? error, params DnsRecordConfiguration[] records)
    {
        var configuration = new DnsConfiguration
        {
            RootServers = new RootServerConfiguration { Addresses = ["198.41.0.4:53"] },
            ListenAddresses = ["udp://127.0.0.1:5353"],
            Records = records
        };
        return configuration.TryValidate(out error);
    }

    private static DnsConfiguration ValidConfig(params DnsRecordConfiguration[] records)
    {
        var configuration = new DnsConfiguration
        {
            RootServers = new RootServerConfiguration { Addresses = ["198.41.0.4:53"] },
            ListenAddresses = ["udp://127.0.0.1:5353"],
            Records = records
        };
        Assert.True(configuration.TryValidate(out var error), error);
        return configuration;
    }

    private static ConfiguredRecordMiddleware CreateMiddleware(DnsConfiguration configuration)
    {
        var monitor = Substitute.For<IOptionsMonitor<DnsConfiguration>>();
        monitor.CurrentValue.Returns(configuration);
        return new ConfiguredRecordMiddleware(PassThroughInner(), monitor);
    }

    private static IDomainMessageMiddleware PassThroughInner()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns((DomainMessage?)null);
        return inner;
    }
}
