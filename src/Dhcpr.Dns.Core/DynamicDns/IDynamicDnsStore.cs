using System.Net;

namespace Dhcpr.Dns.Core.DynamicDns;

public interface IDynamicDnsStore
{
    /// <summary>
    /// TTL applied to answers served from this store.
    /// </summary>
    TimeSpan Ttl { get; }

    /// <summary>
    /// Replaces in-memory entries from the persisted JSON file, if it exists.
    /// </summary>
    void LoadFromDisk();

    /// <summary>
    /// Looks up a dynamic entry by owner name.
    /// </summary>
    /// <returns><see langword="true"/> when <paramref name="name"/> is present.</returns>
    bool TryGet(string name, out DynamicDnsEntry entry);

    /// <summary>
    /// Inserts or updates addresses for <paramref name="name"/>. At least one of
    /// <paramref name="ipv4"/> or <paramref name="ipv6"/> is required.
    /// </summary>
    DynamicDnsUpsertResult Upsert(string name, IPAddress? ipv4, IPAddress? ipv6);
}
