using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Processing.Middleware;

/// <summary>
/// RFC 7873. A query that carries a client cookie gets it echoed, plus a
/// server cookie when one can be minted. Outside the rate limiter so a
/// confirmed cookie is visible before the query is counted, and outside
/// the cache so the stored message does not keep this transaction's cookie.
/// </summary>
public sealed class CookieMiddleware : IDomainMessageMiddleware
{
    public const ushort OptionCode = 10;
    public const int ClientCookieLength = 8;

    private readonly IDomainMessageMiddleware _inner;
    private readonly IDnsServerCookieFactory _cookies;

    public CookieMiddleware(IDomainMessageMiddleware inner, IDnsServerCookieFactory cookies)
    {
        _inner = inner;
        _cookies = cookies;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (!context.IsInternal)
            Capture(context);

        var result = await _inner.ProcessAsync(context, cancellationToken);
        if (context.IsInternal)
            return result;

        return Apply(context.ClientCookie, result, context.ClientEndPoint?.Address);
    }

    private void Capture(DomainMessageContext context)
    {
        var option = TryGetCookieOption(context.DomainMessage);
        if (option is not { Length: >= ClientCookieLength } data)
        {
            context.ClientCookie = null;
            context.CookieConfirmed = false;
            return;
        }

        context.ClientCookie = data[..ClientCookieLength];
        if (data.Length <= ClientCookieLength ||
            context.ClientEndPoint?.Address is not { } client)
        {
            context.CookieConfirmed = false;
            return;
        }

        context.CookieConfirmed = _cookies.IsValid(
            context.ClientCookie.Value.AsSpan(),
            data[ClientCookieLength..].AsSpan(),
            client);
    }

    private DomainMessage Apply(
        ImmutableArray<byte>? clientCookie,
        DomainMessage response,
        IPAddress? clientAddress)
    {
        if (clientCookie is not { Length: >= ClientCookieLength } client)
            return response;

        if (clientAddress is null ||
            !_cookies.TryCreate(client.AsSpan(), clientAddress, out var server))
            return ReplaceCookie(response, client);

        return ReplaceCookie(response, Concat(client, server));
    }

    private static ImmutableArray<byte>? TryGetCookieOption(DomainMessage message)
    {
        foreach (var record in message.Records.Additional)
        {
            if (record.Type is not DomainRecordType.OPT || record.Data is not OptionData data)
                continue;

            foreach (var option in data.Options)
            {
                if (option.Code != OptionCode || option.Data.Length < ClientCookieLength)
                    continue;
                return option.Data;
            }
        }

        return null;
    }

    private static DomainMessage ReplaceCookie(DomainMessage response, ImmutableArray<byte> cookie)
    {
        var additional = response.Records.Additional;
        var optIndex = -1;
        for (var i = 0; i < additional.Length; i++)
        {
            if (additional[i].Type is DomainRecordType.OPT)
            {
                optIndex = i;
                break;
            }
        }

        if (optIndex < 0)
        {
            var opt = new DomainResourceRecord(
                DomainLabels.Empty,
                DomainRecordType.OPT,
                (DomainRecordClass)1232,
                TimeSpan.Zero,
                new OptionData(ImmutableArray.Create(new EdnsOption(OptionCode, cookie))));
            return response with
            {
                Records = response.Records with { Additional = additional.Add(opt) }
            };
        }

        var existingOpt = additional[optIndex];
        var existing = existingOpt.Data as OptionData ?? new OptionData(ImmutableArray<EdnsOption>.Empty);
        var kept = existing.Options.Where(static o => o.Code != OptionCode).ToImmutableArray();
        kept = kept.Add(new EdnsOption(OptionCode, cookie));

        var additionalBuilder = additional.ToBuilder();
        additionalBuilder[optIndex] = existingOpt with { Data = new OptionData(kept) };
        return response with
        {
            Records = response.Records with { Additional = additionalBuilder.ToImmutable() }
        };
    }

    private static ImmutableArray<byte> Concat(ImmutableArray<byte> client, ImmutableArray<byte> server)
    {
        var payload = new byte[client.Length + server.Length];
        client.CopyTo(payload);
        server.CopyTo(payload.AsSpan(client.Length));
        return payload.ToImmutableArray();
    }
}
