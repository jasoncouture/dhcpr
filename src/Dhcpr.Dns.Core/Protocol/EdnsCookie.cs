using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol;

/// <summary>
/// RFC 7873: echo the client's 8-octet cookie plus a server cookie when
/// we can mint one. Do not replay a cached or upstream COOKIE — that is a
/// different transaction. Clients that send no COOKIE are unchanged.
/// </summary>
public static class EdnsCookie
{
    public const ushort OptionCode = 10;
    public const int ClientCookieLength = 8;

    public static void Capture(DomainMessageContext context, IDnsServerCookieFactory? cookies = null)
    {
        // Internal hops already carry the parent's cookie (including null).
        if (context.IsInternal)
            return;

        var option = TryGetCookieOption(context.DomainMessage);
        if (option is not { Length: >= ClientCookieLength } data)
        {
            context.ClientCookie = null;
            context.CookieConfirmed = false;
            return;
        }

        context.ClientCookie = data[..ClientCookieLength];
        if (cookies is null ||
            data.Length <= ClientCookieLength ||
            context.ClientEndPoint?.Address is not { } client)
        {
            context.CookieConfirmed = false;
            return;
        }

        context.CookieConfirmed = cookies.IsValid(
            context.ClientCookie.Value.AsSpan(),
            data[ClientCookieLength..].AsSpan(),
            client);
    }

    public static DomainMessage Apply(DomainMessage request, DomainMessage response)
        => Apply(TryGetClientCookie(request), response);

    public static DomainMessage Apply(ImmutableArray<byte>? clientCookie, DomainMessage response)
        => Apply(clientCookie, response, cookies: null, clientAddress: null);

    public static DomainMessage Apply(
        ImmutableArray<byte>? clientCookie,
        DomainMessage response,
        IDnsServerCookieFactory? cookies,
        IPAddress? clientAddress)
    {
        if (clientCookie is not { Length: >= ClientCookieLength } client)
            return response;

        if (cookies is null ||
            clientAddress is null ||
            !cookies.TryCreate(client.AsSpan(), clientAddress, out var server))
            return ReplaceCookie(response, client);

        return ReplaceCookie(response, Concat(client, server));
    }

    public static ImmutableArray<byte>? TryGetClientCookie(DomainMessage message)
    {
        var option = TryGetCookieOption(message);
        return option is { Length: >= ClientCookieLength } data
            ? data[..ClientCookieLength]
            : null;
    }

    public static ImmutableArray<byte>? TryGetCookieOption(DomainMessage message)
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

    public static DomainResourceRecords StripCookies(DomainResourceRecords records)
    {
        var additional = records.Additional;
        if (additional.IsDefaultOrEmpty)
            return records;

        var changed = false;
        var builder = ImmutableArray.CreateBuilder<DomainResourceRecord>(additional.Length);
        foreach (var record in additional)
        {
            if (record.Type is not DomainRecordType.OPT ||
                record.Data is not OptionData data ||
                !data.Options.Any(static o => o.Code == OptionCode))
            {
                builder.Add(record);
                continue;
            }

            var kept = data.Options.Where(static o => o.Code != OptionCode).ToImmutableArray();
            builder.Add(record with { Data = new OptionData(kept) });
            changed = true;
        }

        return changed ? records with { Additional = builder.ToImmutable() } : records;
    }

    private static DomainMessage ReplaceCookie(DomainMessage response, ImmutableArray<byte>? clientCookie)
    {
        if (clientCookie is not { Length: >= ClientCookieLength } cookie)
            return response;

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
        return ImmutableArray.Create(payload);
    }
}
