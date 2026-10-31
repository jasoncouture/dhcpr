using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.Processing.Middleware;
using Dhcpr.Dns.Core.Protocol.RecordData;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class CookieMiddlewareTests
{
    [Fact]
    public async Task ReplacesStaleCookieWithRequestClientCookie()
    {
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var stale = ImmutableArray.Create<byte>(9, 9, 9, 9, 9, 9, 9, 9, 10, 10);
        var request = WithOptCookie(DomainMessage.CreateRequest("example.com", DomainRecordType.A), clientCookie);
        var response = DomainMessage.CreateResponse(
            request,
            additional: [OptWithCookie(stale)],
            responseCode: DomainResponseCode.NoError);

        var (applied, _) = await Run(request, response);

        var cookie = Assert.Single(CookieOptions(applied));
        Assert.Equal(clientCookie.ToArray(), cookie.Data.ToArray());
    }

    [Fact]
    public async Task LeavesResponseAloneWhenCookieIsAbsent()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            additional: [OptWithCookie(ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8))],
            responseCode: DomainResponseCode.NoError);

        var (applied, context) = await Run(request, response);

        Assert.Same(response, applied);
        Assert.Null(context.ClientCookie);
        Assert.False(context.CookieConfirmed);
    }

    [Fact]
    public async Task AddsOptWhenResponseHasNone()
    {
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var request = WithOptCookie(DomainMessage.CreateRequest("example.com", DomainRecordType.A), clientCookie);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);

        var (applied, _) = await Run(request, response);

        var cookie = Assert.Single(CookieOptions(applied));
        Assert.Equal(clientCookie.ToArray(), cookie.Data.ToArray());
    }

    [Fact]
    public async Task CaptureReadsCookieOnceAndSkipsInternalHops()
    {
        var cookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var request = WithOptCookie(DomainMessage.CreateRequest("example.com", DomainRecordType.A), cookie);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);

        var (_, context) = await Run(request, response);
        Assert.Equal(cookie.ToArray(), context.ClientCookie!.Value.ToArray());

        var internalContext = context with
        {
            IsInternal = true,
            ClientCookie = null
        };
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(response);
        var middleware = new CookieMiddleware(inner, Factory());

        var result = await middleware.ProcessAsync(internalContext, CancellationToken.None);

        Assert.Same(response, result);
        Assert.Null(internalContext.ClientCookie);
    }

    [Fact]
    public async Task AppendsServerCookie()
    {
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var request = WithOptCookie(DomainMessage.CreateRequest("example.com", DomainRecordType.A), clientCookie);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var factory = Factory(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());
        var client = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000);

        var (applied, _) = await Run(request, response, factory, client);

        var cookie = Assert.Single(CookieOptions(applied));
        var payload = cookie.Data.AsSpan();
        Assert.Equal(CookieMiddleware.ClientCookieLength + DnsServerCookieFactory.ServerCookieLength, payload.Length);
        Assert.True(payload[..CookieMiddleware.ClientCookieLength].SequenceEqual(clientCookie.AsSpan()));
        Assert.True(factory.IsValid(
            payload[..CookieMiddleware.ClientCookieLength],
            payload[CookieMiddleware.ClientCookieLength..],
            client.Address));
    }

    [Fact]
    public async Task ConfirmsValidServerCookie()
    {
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var client = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000);
        var factory = Factory(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());
        var server = factory.Create(clientCookie.AsSpan(), client.Address);
        var request = WithOptCookie(
            DomainMessage.CreateRequest("example.com", DomainRecordType.A),
            clientCookie.AddRange(server));
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);

        var (_, context) = await Run(request, response, factory, client);

        Assert.Equal(clientCookie.ToArray(), context.ClientCookie!.Value.ToArray());
        Assert.True(context.CookieConfirmed);
    }

    [Fact]
    public async Task EchoesClientCookieWhenSecretIsMissing()
    {
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var request = WithOptCookie(DomainMessage.CreateRequest("example.com", DomainRecordType.A), clientCookie);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var client = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000);

        var (applied, context) = await Run(request, response, Factory(), client);

        var cookie = Assert.Single(CookieOptions(applied));
        Assert.Equal(clientCookie.ToArray(), cookie.Data.ToArray());
        Assert.False(context.CookieConfirmed);
    }

    [Fact]
    public async Task ClientCookieAloneIsNotConfirmed()
    {
        var clientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8);
        var request = WithOptCookie(DomainMessage.CreateRequest("example.com", DomainRecordType.A), clientCookie);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var client = new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53_000);
        var factory = Factory(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());

        var (_, context) = await Run(request, response, factory, client);

        Assert.Equal(clientCookie.ToArray(), context.ClientCookie!.Value.ToArray());
        Assert.False(context.CookieConfirmed);
    }

    private static async Task<(DomainMessage Message, DomainMessageContext Context)> Run(
        DomainMessage request,
        DomainMessage response,
        IDnsServerCookieFactory? cookies = null,
        IPEndPoint? client = null)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(response);
        var middleware = new CookieMiddleware(inner, cookies ?? Factory());
        var context = new DomainMessageContext(client, null, request);
        var message = await middleware.ProcessAsync(context, CancellationToken.None);
        return (message, context);
    }

    private static DnsServerCookieFactory Factory(byte[]? secret = null)
    {
        var source = Substitute.For<IDnsServerCookieSecretSource>();
        if (secret is not null)
        {
            source.TryGetSecret(out Arg.Any<ReadOnlyMemory<byte>>())
                .Returns(call =>
                {
                    call[0] = new ReadOnlyMemory<byte>(secret);
                    return true;
                });
        }

        return new DnsServerCookieFactory(source, TimeProvider.System);
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
            new OptionData(ImmutableArray.Create(new EdnsOption(CookieMiddleware.OptionCode, cookie))));

    private static IEnumerable<EdnsOption> CookieOptions(DomainMessage message)
        => message.Records.Additional
            .Where(r => r.Type is DomainRecordType.OPT && r.Data is OptionData)
            .SelectMany(r => ((OptionData)r.Data).Options)
            .Where(o => o.Code == CookieMiddleware.OptionCode);
}
