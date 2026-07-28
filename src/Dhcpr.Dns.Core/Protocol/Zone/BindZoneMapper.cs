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
                => Rr(name, DomainRecordType.A, ttl, new IPAddressData(a.Address)),
            AaaaResourceRecord aaaa when aaaa.Address.AddressFamily == AddressFamily.InterNetworkV6
                => Rr(name, DomainRecordType.AAAA, ttl, new IPAddressData(aaaa.Address)),
            NsResourceRecord ns
                => Rr(name, DomainRecordType.NS, ttl, new NameData(ToLabels(ns.NameServer))),
            CNameResourceRecord cname
                => Rr(name, DomainRecordType.CNAME, ttl, new NameData(ToLabels(cname.CanonicalName))),
            DNameResourceRecord dname
                => Rr(name, DomainRecordType.DNAME, ttl, new NameData(ToLabels(dname.Target))),
            AliasResourceRecord alias
                => Rr(name, DomainRecordType.ALIAS, ttl, new NameData(ToLabels(alias.Target))),
            PtrResourceRecord ptr
                => Rr(name, DomainRecordType.PTR, ttl, new NameData(ToLabels(ptr.HostName))),
            MxResourceRecord mx
                => Rr(name, DomainRecordType.MX, ttl, new MailExchangerData(mx.Preference, ToLabels(mx.Exchange))),
            TxtResourceRecord txt
                => Rr(name, DomainRecordType.TXT, ttl, new TextData(txt.Content)),
            HInfoResourceRecord hinfo
                => Rr(name, DomainRecordType.HINFO, ttl, new HostInformationData(hinfo.Cpu, hinfo.Os)),
            SrvResourceRecord srv
                => Rr(name, DomainRecordType.SRV, ttl, new ServiceData(srv.Priority, srv.Weight, srv.Port, ToLabels(srv.Target))),
            CAAResourceRecord caa
                => Rr(name, DomainRecordType.CAA, ttl,
                    new CertificationAuthorityAuthorizationData((byte)caa.Flag, caa.Tag, caa.Value)),
            TLSAResourceRecord tlsa
                => Rr(name, DomainRecordType.TLSA, ttl,
                    new TlsAssociationData(
                        (byte)tlsa.CertificateUsage,
                        (byte)tlsa.Selector,
                        (byte)tlsa.MatchingType,
                        Convert.FromHexString(tlsa.CertificateAssociationData.Replace(" ", "", StringComparison.Ordinal))
                            .ToImmutableArray())),
            SSHFPResourceRecord sshfp
                => Rr(name, DomainRecordType.SSHFP, ttl,
                    new SshFingerprintData(
                        (byte)sshfp.AlgorithmNumber,
                        (byte)sshfp.FingerprintType,
                        Convert.FromHexString(sshfp.Fingerprint.Replace(" ", "", StringComparison.Ordinal))
                            .ToImmutableArray())),
            NaptrResourceRecord naptr
                => Rr(name, DomainRecordType.NAPTR, ttl,
                    new NamingAuthorityPointerData(
                        naptr.Order,
                        naptr.Preference,
                        naptr.Flags,
                        naptr.Services,
                        naptr.Regexp,
                        ToLabels(naptr.Replacement))),
            LuaResourceRecord lua
                => Rr(name, DomainRecordType.LUA, ttl, new LuaRecordData(lua.TargetType, lua.Script)),
            SoaResourceRecord soa
                => MapSoa(name, ttl, soa),
            DsResourceRecord ds
                => MapDs(name, ttl, ds),
            _ => null
        };
    }

    private static DomainResourceRecord Rr(
        DomainLabels name,
        DomainRecordType type,
        TimeSpan ttl,
        IDomainResourceRecordData data)
        => new(name, type, DomainRecordClass.IN, ttl, data);

    private static DomainResourceRecord MapSoa(DomainLabels name, TimeSpan ttl, SoaResourceRecord soa)
    {
        if (!int.TryParse(soa.SerialNumber, NumberStyles.Integer, CultureInfo.InvariantCulture, out var serial))
            throw new FormatException($"Invalid SOA serial '{soa.SerialNumber}'");

        return Rr(
            name,
            DomainRecordType.SOA,
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
        return Rr(
            name,
            DomainRecordType.DS,
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
