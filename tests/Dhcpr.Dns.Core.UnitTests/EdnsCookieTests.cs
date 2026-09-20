using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.UnitTests;

public class EdnsCookieTests
{
    [Fact]
    public void ApplyReplacesStaleCookieWithRequestClientCookie()
    {
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var stale = ImmutableArray.Create<byte>(9, 9, 9, 9, 9, 9, 9, 9, 10, 10);
        var request = WithOptCookie(DomainMessage.CreateRequest("example.com", DomainRecordType.A), clientCookie);
        var response = DomainMessage.CreateResponse(
            request,
            additional: [OptWithCookie(stale)],
            responseCode: DomainResponseCode.NoError);

        var applied = EdnsCookie.Apply(request, response);
        var cookie = Assert.Single(CookieOptions(applied));
        Assert.Equal(clientCookie, cookie.Data);
    }

    [Fact]
    public void ApplyLeavesResponseAloneWhenCookieIsNull()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            additional: [OptWithCookie(ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8))],
            responseCode: DomainResponseCode.NoError);

        var applied = EdnsCookie.Apply((ImmutableArray<byte>?)null, response);
        Assert.Same(response, applied);
    }

    [Fact]
    public void ApplyAddsOptWhenResponseHasNone()
    {
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var request = WithOptCookie(DomainMessage.CreateRequest("example.com", DomainRecordType.A), clientCookie);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);

        var applied = EdnsCookie.Apply(request, response);
        var cookie = Assert.Single(CookieOptions(applied));
        Assert.Equal(clientCookie, cookie.Data);
    }

    [Fact]
    public void CaptureSetsNullWhenRequestHasNoCookie()
    {
        var context = new DomainMessageContext(
            null,
            null,
            DomainMessage.CreateRequest("example.com", DomainRecordType.A));

        EdnsCookie.Capture(context);
        Assert.Null(context.ClientCookie);
        Assert.False(context.CookieConfirmed);
    }

    [Fact]
    public void CaptureReadsCookieOnce()
    {
        var cookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var context = new DomainMessageContext(
            null,
            null,
            WithOptCookie(DomainMessage.CreateRequest("example.com", DomainRecordType.A), cookie));

        EdnsCookie.Capture(context);
        Assert.Equal(cookie, context.ClientCookie);

        var internalContext = context with
        {
            IsInternal = true,
            ClientCookie = null
        };
        EdnsCookie.Capture(internalContext);
        Assert.Null(internalContext.ClientCookie);
    }

    [Fact]
    public void ApplyUsesCapturedCookieWithoutRereadingRequest()
    {
        var cookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);

        var applied = EdnsCookie.Apply(cookie, response);
        var echoed = Assert.Single(CookieOptions(applied));
        Assert.Equal(cookie, echoed.Data);
    }

    [Fact]
    public void StripCookiesRemovesCookieOption()
    {
        var records = new DomainResourceRecords(
            ImmutableArray<DomainResourceRecord>.Empty,
            ImmutableArray<DomainResourceRecord>.Empty,
            ImmutableArray.Create(OptWithCookie(ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8))));

        var stripped = EdnsCookie.StripCookies(records);
        Assert.DoesNotContain(
            ((OptionData)stripped.Additional[0].Data).Options,
            o => o.Code == EdnsCookie.OptionCode);
    }

    [Fact]
    public void Apply_WithFactory_AppendsServerCookie()
    {
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var factory = new DnsServerCookieFactory(
            new StaticDnsServerCookieSecretSource(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray()),
            TimeProvider.System);
        var client = IPAddress.Parse("203.0.113.10");

        var applied = EdnsCookie.Apply(clientCookie, response, factory, client);
        var cookie = Assert.Single(CookieOptions(applied));
        var payload = cookie.Data.AsSpan();
        Assert.Equal(EdnsCookie.ClientCookieLength + DnsServerCookieFactory.ServerCookieLength, payload.Length);
        Assert.True(payload[..EdnsCookie.ClientCookieLength].SequenceEqual(clientCookie.AsSpan()));
        Assert.True(factory.IsValid(
            payload[..EdnsCookie.ClientCookieLength],
            payload[EdnsCookie.ClientCookieLength..],
            client));
    }

    [Fact]
    public void Capture_ConfirmsValidServerCookie()
    {
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var client = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000);
        var factory = new DnsServerCookieFactory(
            new StaticDnsServerCookieSecretSource(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray()),
            TimeProvider.System);
        var server = factory.Create(clientCookie.AsSpan(), client.Address);
        var payload = clientCookie.AddRange(server);
        var context = new DomainMessageContext(
            client,
            new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53),
            WithOptCookie(DomainMessage.CreateRequest("example.com", DomainRecordType.A), payload));

        EdnsCookie.Capture(context, factory);

        Assert.Equal(clientCookie, context.ClientCookie);
        Assert.True(context.CookieConfirmed);
    }

    [Fact]
    public void Apply_WithoutSecret_EchoesClientCookieOnly()
    {
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var factory = new DnsServerCookieFactory(new EmptyDnsServerCookieSecretSource(), TimeProvider.System);

        var applied = EdnsCookie.Apply(clientCookie, response, factory, IPAddress.Parse("203.0.113.10"));
        var cookie = Assert.Single(CookieOptions(applied));
        Assert.Equal(clientCookie, cookie.Data);
    }

    [Fact]
    public void Capture_DoesNotRequireCookie()
    {
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000),
            new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53),
            DomainMessage.CreateRequest("example.com", DomainRecordType.A));
        var factory = new DnsServerCookieFactory(
            new StaticDnsServerCookieSecretSource(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray()),
            TimeProvider.System);

        EdnsCookie.Capture(context, factory);

        Assert.Null(context.ClientCookie);
        Assert.False(context.CookieConfirmed);
    }

    [Fact]
    public void Capture_ClientCookieOnly_IsNotConfirmed()
    {
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000),
            new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53),
            WithOptCookie(DomainMessage.CreateRequest("example.com", DomainRecordType.A), clientCookie));
        var factory = new DnsServerCookieFactory(
            new StaticDnsServerCookieSecretSource(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray()),
            TimeProvider.System);

        EdnsCookie.Capture(context, factory);

        Assert.Equal(clientCookie, context.ClientCookie);
        Assert.False(context.CookieConfirmed);
    }

    private static DomainMessage WithOptCookie(DomainMessage message, ImmutableArray<byte> cookie)
        => message with
        {
            Records = message.Records with
            {
                Additional = ImmutableArray.Create(OptWithCookie(cookie))
            }
        };

    private static DomainResourceRecord OptWithCookie(ImmutableArray<byte> cookie)
        => new(
            DomainLabels.Empty,
            DomainRecordType.OPT,
            (DomainRecordClass)1232,
            TimeSpan.Zero,
            new OptionData(ImmutableArray.Create(new EdnsOption(EdnsCookie.OptionCode, cookie))));

    private static IEnumerable<EdnsOption> CookieOptions(DomainMessage message)
        => message.Records.Additional
            .Where(r => r.Type is DomainRecordType.OPT && r.Data is OptionData)
            .SelectMany(r => ((OptionData)r.Data).Options)
            .Where(o => o.Code == EdnsCookie.OptionCode);
}