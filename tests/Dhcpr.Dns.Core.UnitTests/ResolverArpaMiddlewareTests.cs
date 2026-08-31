using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class ResolverArpaMiddlewareTests
{
    [Fact]
    public async Task OtherNamesPassThrough()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage?>(response));

        var middleware = Create(inner);
        var result = await middleware.ProcessAsync(Context(request), CancellationToken.None);

        Assert.Same(response, result);
        await inner.Received(1).ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Theory]
    [InlineData("resolver.arpa", DomainRecordType.A)]
    [InlineData("foo.resolver.arpa", DomainRecordType.A)]
    [InlineData("_dns.resolver.arpa", DomainRecordType.A)]
    [InlineData("_dns.resolver.arpa", DomainRecordType.HTTPS)]
    [InlineData("_dns.resolver.arpa", DomainRecordType.NS)]
    public async Task NamesUnderResolverArpaReturnNodataWithoutCallingInner(
        string qname,
        DomainRecordType type)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = Create(inner, new DesignatedResolverConfiguration
        {
            Priority = 1,
            Target = "dns.example.com"
        });
        var request = DomainMessage.CreateRequest(qname, type);
        var context = Context(request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Empty(result.Records.Answers);
        Assert.True(result.Flags.Authoritative);
        Assert.True(result.Flags.RecursionAvailable);
        Assert.True(context.CacheHit);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DiscoverySvcbWithoutConfigReturnsNodata()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = Create(inner);
        var request = DomainMessage.CreateRequest("_dns.resolver.arpa", DomainRecordType.SVCB);

        var result = await middleware.ProcessAsync(Context(request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Empty(result.Records.Answers);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DiscoverySvcbReturnsConfiguredAnswersAndHints()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var middleware = Create(inner, new DesignatedResolverConfiguration
        {
            Priority = 1,
            Target = "dns.example.com",
            Alpn = ["h2"],
            Port = 443,
            DohPath = "/dns-query{?dns}",
            Ipv4Hint = ["192.0.2.1"],
            Ipv6Hint = ["2001:db8::1"]
        });
        var request = DomainMessage.CreateRequest("_dns.resolver.arpa", DomainRecordType.SVCB);
        var context = Context(request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal("resolver.arpa", context.AnsweredBy);
        Assert.True(context.DoNotCacheResponse);
        Assert.True(context.CacheHit);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        var svcb = Assert.IsType<SvcbData>(Assert.Single(result.Records.Answers).Data);
        Assert.Equal((ushort)1, svcb.Priority);
        Assert.Equal("dns.example.com", svcb.TargetName.ToString());
        Assert.Contains(svcb.Parameters, p => p.Key is SvcbParameterKey.Alpn);
        Assert.Contains(svcb.Parameters, p => p.Key is SvcbParameterKey.DohPath);
        Assert.Equal(2, result.Records.Additional.Length);
        Assert.Contains(result.Records.Additional, r => r.Type is DomainRecordType.A);
        Assert.Contains(result.Records.Additional, r => r.Type is DomainRecordType.AAAA);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DiscoverySvcbUsesTlsCertificateWhenDesignatedResolversEmpty()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var tls = new TlsConfiguration
        {
            Enabled = true,
            Listeners = ["0.0.0.0:853"],
            HttpsPort = 443,
            CertificatePath = "tls.crt",
            PrivateKeyPath = "tls.key"
        };
        Assert.True(tls.TryValidate(out _));
        var certificates = Substitute.For<ITlsServerCertificateProvider>();
        certificates.GetCertificate().Returns(SelfSigned("dns.example.com"));
        var middleware = Create(inner, [], tls, certificates);
        var request = DomainMessage.CreateRequest("_dns.resolver.arpa", DomainRecordType.SVCB);

        var result = await middleware.ProcessAsync(Context(request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(2, result!.Records.Answers.Length);
        var first = Assert.IsType<SvcbData>(result.Records.Answers[0].Data);
        var second = Assert.IsType<SvcbData>(result.Records.Answers[1].Data);
        Assert.Equal("dns.example.com", first.TargetName.ToString());
        Assert.Equal("dns.example.com", second.TargetName.ToString());
        Assert.Contains(first.Parameters, p => p.Key is SvcbParameterKey.Alpn);
        Assert.Contains(second.Parameters, p => p.Key is SvcbParameterKey.DohPath);
        await inner.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public void TryValidate_RejectsResolverArpaTarget()
    {
        var dns = ValidDns();
        dns.DesignatedResolvers =
        [
            new DesignatedResolverConfiguration { Target = "resolver.arpa" }
        ];
        Assert.False(dns.TryValidate(out var error));
        Assert.Contains("resolver.arpa", error);
    }

    [Fact]
    public void TryValidate_AcceptsDesignatedResolver()
    {
        var dns = ValidDns();
        dns.DesignatedResolvers =
        [
            new DesignatedResolverConfiguration
            {
                Target = "dns.example.com",
                Alpn = ["h2"],
                DohPath = "/dns-query{?dns}",
                Ipv4Hint = ["192.0.2.1"]
            }
        ];
        Assert.True(dns.TryValidate(out var error), error);
    }

    private static ResolverArpaMiddleware Create(
        IDomainMessageMiddleware inner,
        params DesignatedResolverConfiguration[] designated)
        => Create(inner, designated, tls: null, certificates: null);

    private static ResolverArpaMiddleware Create(
        IDomainMessageMiddleware inner,
        DesignatedResolverConfiguration[] designated,
        TlsConfiguration? tls,
        ITlsServerCertificateProvider? certificates)
    {
        var dns = Substitute.For<IOptionsMonitor<DnsConfiguration>>();
        dns.CurrentValue.Returns(new DnsConfiguration { DesignatedResolvers = designated });
        var tlsMonitor = Substitute.For<IOptionsMonitor<TlsConfiguration>>();
        tlsMonitor.CurrentValue.Returns(tls ?? new TlsConfiguration());
        certificates ??= Substitute.For<ITlsServerCertificateProvider>();
        return new ResolverArpaMiddleware(inner, dns, tlsMonitor, certificates);
    }

    private static X509Certificate2 SelfSigned(string commonName)
    {
        using var key = ECDsa.Create();
        var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    private static DomainMessageContext Context(DomainMessage request)
        => new(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

    private static DnsConfiguration ValidDns()
        => new()
        {
            ListenAddresses = ["udp://127.0.0.1:53"]
        };
}
