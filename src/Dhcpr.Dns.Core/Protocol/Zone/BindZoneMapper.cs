using System.Collections.Immutable;
using System.Globalization;
using System.Net.Sockets;

using Dhcpr.Dns.Core.Protocol.RecordData;

using DnsZone.Records;

namespace Dhcpr.Dns.Core.Protocol.Zone;

public static class BindZoneMapper
{
    public static IReadOnlyList<DomainResourceRecord> MapAll(IEnumerable<ResourceRecord> records)
    {
        var list = new List<DomainResourceRecord>();
        foreach (var record in records)
        {
            if (TryMap(record) is { } mapped)
                list.Add(mapped);
        }

        return list;
    }

    public static DomainResourceRecord? TryMap(ResourceRecord record)
    {
        var name = ToLabels(record.Name);
        var ttl = record.Ttl;

        return record switch
        {
            AResourceRecord a when a.Address.AddressFamily == AddressFamily.InterNetwork
                => new DomainResourceRecord(name, DomainRecordType.A, DomainRecordClass.IN, ttl, new IPAddressData(a.Address)),
            AaaaResourceRecord aaaa when aaaa.Address.AddressFamily == AddressFamily.InterNetworkV6
                => new DomainResourceRecord(name, DomainRecordType.AAAA, DomainRecordClass.IN, ttl, new IPAddressData(aaaa.Address)),
            NsResourceRecord ns
                => new DomainResourceRecord(name, DomainRecordType.NS, DomainRecordClass.IN, ttl, new NameData(ToLabels(ns.NameServer))),
            CNameResourceRecord cname
                => new DomainResourceRecord(name, DomainRecordType.CNAME, DomainRecordClass.IN, ttl, new NameData(ToLabels(cname.CanonicalName))),
            PtrResourceRecord ptr
                => new DomainResourceRecord(name, DomainRecordType.PTR, DomainRecordClass.IN, ttl, new NameData(ToLabels(ptr.HostName))),
            MxResourceRecord mx
                => new DomainResourceRecord(name, DomainRecordType.MX, DomainRecordClass.IN, ttl, new MailExchangerData(mx.Preference, ToLabels(mx.Exchange))),
            TxtResourceRecord txt
                => new DomainResourceRecord(name, DomainRecordType.TXT, DomainRecordClass.IN, ttl, new TextData(txt.Content)),
            SrvResourceRecord srv
                => new DomainResourceRecord(name, DomainRecordType.SRV, DomainRecordClass.IN, ttl,
                    new ServiceData(srv.Priority, srv.Weight, srv.Port, ToLabels(srv.Target))),
            SoaResourceRecord soa
                => MapSoa(name, ttl, soa),
            DsResourceRecord ds
                => MapDs(name, ttl, ds),
            _ => null
        };
    }

    private static DomainResourceRecord MapSoa(DomainLabels name, TimeSpan ttl, SoaResourceRecord soa)
    {
        if (!int.TryParse(soa.SerialNumber, NumberStyles.Integer, CultureInfo.InvariantCulture, out var serial))
            throw new FormatException($"Invalid SOA serial '{soa.SerialNumber}'");

        return new DomainResourceRecord(
            name,
            DomainRecordType.SOA,
            DomainRecordClass.IN,
            ttl,
            new StartOfAuthorityData(
                ToLabels(soa.NameServer),
                ToLabels(soa.ResponsibleEmail),
                serial,
                soa.Refresh,
                soa.Retry,
                soa.Expiry,
                soa.Minimum));
    }

    private static DomainResourceRecord MapDs(DomainLabels name, TimeSpan ttl, DsResourceRecord ds)
    {
        if (!ushort.TryParse(ds.KeyTag, NumberStyles.Integer, CultureInfo.InvariantCulture, out var keyTag))
            throw new FormatException($"Invalid DS key tag '{ds.KeyTag}'");

        var hex = ds.Hash.Replace(" ", "", StringComparison.Ordinal);
        return new DomainResourceRecord(
            name,
            DomainRecordType.DS,
            DomainRecordClass.IN,
            ttl,
            new DelegationSignerData(
                keyTag,
                (DnssecAlgorithmType)ds.Algorithm,
                (DelegationSignerDigestType)ds.HashType,
                Convert.FromHexString(hex).ToImmutableArray()));
    }

    private static DomainLabels ToLabels(string name)
    {
        name = name.Trim().TrimEnd('.');
        return string.IsNullOrEmpty(name) ? DomainLabels.Empty : new DomainLabels(name);
    }
}
