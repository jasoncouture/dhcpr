using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol;

/// <summary>
/// RFC 7873: echo the client's 8-octet cookie in our OPT. Do not replay a
/// cached or upstream COOKIE — that is a different transaction.
/// </summary>
public static class EdnsCookie
{
    public const ushort OptionCode = 10;
    public const int ClientCookieLength = 8;

    public static DomainMessage Apply(DomainMessage request, DomainMessage response)
        => ReplaceCookie(response, TryGetClientCookie(request));

    public static ImmutableArray<byte>? TryGetClientCookie(DomainMessage message)
    {
        foreach (var record in message.Records.Additional)
        {
            if (record.Type is not DomainRecordType.OPT || record.Data is not OptionData data)
                continue;

            foreach (var option in data.Options)
            {
                if (option.Code != OptionCode || option.Data.Length < ClientCookieLength)
                    continue;
                return option.Data[..ClientCookieLength];
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
            if (clientCookie is null)
                return response;

            var opt = new DomainResourceRecord(
                DomainLabels.Empty,
                DomainRecordType.OPT,
                (DomainRecordClass)1232,
                TimeSpan.Zero,
                new OptionData(ImmutableArray.Create(new EdnsOption(OptionCode, clientCookie.Value))));
            return response with
            {
                Records = response.Records with { Additional = additional.Add(opt) }
            };
        }

        var existingOpt = additional[optIndex];
        var existing = existingOpt.Data as OptionData ?? new OptionData(ImmutableArray<EdnsOption>.Empty);
        var kept = existing.Options.Where(static o => o.Code != OptionCode).ToImmutableArray();
        if (clientCookie is { } cookie)
            kept = kept.Add(new EdnsOption(OptionCode, cookie));

        if (kept.Length == existing.Options.Length &&
            clientCookie is null &&
            existing.Options.All(static o => o.Code != OptionCode))
            return response;

        var additionalBuilder = additional.ToBuilder();
        additionalBuilder[optIndex] = existingOpt with { Data = new OptionData(kept) };
        return response with
        {
            Records = response.Records with { Additional = additionalBuilder.ToImmutable() }
        };
    }
}
