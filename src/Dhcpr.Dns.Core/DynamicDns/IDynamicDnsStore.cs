using System.Net;

namespace Dhcpr.Dns.Core.DynamicDns;

public interface IDynamicDnsStore
{
    TimeSpan Ttl { get; }
    void LoadFromDisk();
    bool TryGet(string name, out DynamicDnsEntry entry);
    DynamicDnsUpsertResult Upsert(string name, IPAddress? ipv4, IPAddress? ipv6);
}
