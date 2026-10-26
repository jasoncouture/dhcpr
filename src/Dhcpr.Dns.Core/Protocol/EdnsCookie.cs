using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol;

/// <summary>
/// Option 10, removed before a message is stored.
/// </summary>
public static class EdnsCookie
{
    public const ushort OptionCode = 10;
    public const int ClientCookieLength = 8;

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
}
