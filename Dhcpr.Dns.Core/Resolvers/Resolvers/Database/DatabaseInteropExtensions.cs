using System.Net;

using Dhcpr.Data.Dns.Models;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Riok.Mapperly.Abstractions;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Database;

[Mapper]
public static partial class DatabaseInteropExtensions
{
    public static async Task<bool> ToResourceRecords(this IAsyncEnumerable<DnsResourceRecord> records, IResponse response, CancellationToken cancellationToken)
    {
        bool any = false;
        await foreach (var item in records.WithCancellation(cancellationToken))
        {
            any = true;
            var list = item.Section switch
            {
                ResourceRecordSection.Answer => response.AnswerRecords,
                ResourceRecordSection.Additional => response.AdditionalRecords,
                ResourceRecordSection.Authority => response.AuthorityRecords,
                _ => throw new NotSupportedException("Unknown record section, this should not happen")
            };
            list.Add(ToResourceRecord(item));
        }

        return any;
    }

    public static partial IResourceRecord ToResourceRecord<T>(this T record);

    private static IResourceRecord MapToResourceRecord(InterNetworkVersion6AddressDnsResourceRecord record)
        => new IPAddressResourceRecord(new Domain(record.Parent.Name),
            new IPAddress(record.InterNetworkVersion6Address), record.TimeToLive);


    private static IResourceRecord MapToResourceRecord(InterNetworkVersion4AddressResourceRecord record)
        => new IPAddressResourceRecord(new Domain(record.Parent.Name),
            new IPAddress(record.InterNetworkVersion4Address), record.TimeToLive);
}