using System.Net;

using Dhcpr.Core.Linq;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public static class ResponseExtensions
{
    public static PooledList<IResourceRecord> ToResourceRecordPooledList(this IResponse response) =>
        response.AnswerRecords
            .Concat(response.AuthorityRecords)
            .Concat(response.AdditionalRecords)
            .ToPooledList();

    public static IResourceRecord Clone(this IResourceRecord resourceRecord, TimeSpan? ttlOverride = null)
    {
        // I really hate this. I am going to eventually write my own library for this server.
        // Or I may fork this package, and submodule it.
        var ttl = ttlOverride ?? resourceRecord.TimeToLive;
        if (ttl < TimeSpan.Zero) ttl = TimeSpan.FromSeconds(0);
        return resourceRecord switch
        {
            CanonicalNameResourceRecord canonicalNameResourceRecord =>
                new CanonicalNameResourceRecord(
                    canonicalNameResourceRecord.Name,
                    canonicalNameResourceRecord.CanonicalDomainName,
                    ttl
                ),
            IPAddressResourceRecord ipAddressResourceRecord =>
                new IPAddressResourceRecord(
                    ipAddressResourceRecord.Name,
                    ipAddressResourceRecord.IPAddress,
                    ttl
                ),
            MailExchangeResourceRecord mailExchangeResourceRecord =>
                new MailExchangeResourceRecord(
                    mailExchangeResourceRecord.Name,
                    mailExchangeResourceRecord.Preference,
                    mailExchangeResourceRecord.ExchangeDomainName,
                    ttl
                ),
            NameServerResourceRecord nameServerResourceRecord =>
                new NameServerResourceRecord(
                    nameServerResourceRecord.Name,
                    nameServerResourceRecord.NSDomainName,
                    ttl
                ),
            PointerResourceRecord pointerResourceRecord =>
                new PointerResourceRecord(
                    IPAddress.Parse(pointerResourceRecord.Name.ToString()!),
                    pointerResourceRecord.PointerDomainName,
                    ttl
                ),
            ServiceResourceRecord serviceResourceRecord =>
                new ServiceResourceRecord(
                    serviceResourceRecord.Name,
                    serviceResourceRecord.Priority,
                    serviceResourceRecord.Weight,
                    serviceResourceRecord.Port,
                    serviceResourceRecord.Target, ttl
                ),
            StartOfAuthorityResourceRecord startOfAuthorityResourceRecord =>
                new StartOfAuthorityResourceRecord(
                    startOfAuthorityResourceRecord.Name,
                    startOfAuthorityResourceRecord.MasterDomainName,
                    startOfAuthorityResourceRecord.ResponsibleDomainName,
                    startOfAuthorityResourceRecord.SerialNumber,
                    startOfAuthorityResourceRecord.RefreshInterval,
                    startOfAuthorityResourceRecord.RetryInterval,
                    startOfAuthorityResourceRecord.ExpireInterval,
                    startOfAuthorityResourceRecord.MinimumTimeToLive,
                    ttl
                ),
            TextResourceRecord textResourceRecord =>
                new TextResourceRecord(
                    textResourceRecord.Name,
                    textResourceRecord.Attribute.Key,
                    textResourceRecord.Attribute.Value,
                    ttl
                ),
            _ => throw new ArgumentOutOfRangeException(nameof(resourceRecord))
        };
    }
}