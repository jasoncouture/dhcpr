using System.Net;

using Dhcpr.Data;
using Dhcpr.Data.Dns.Models;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

using Riok.Mapperly.Abstractions;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Database;

public class DatabaseResolver : IDatabaseResolver
{
    private readonly IServiceProvider _serviceProvider;

    public DatabaseResolver(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task<IResponse?> Resolve(IRequest request, CancellationToken cancellationToken = default)
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<DataContext>();
        var question = request.Questions.Single();
        var questionDomain = question.Name.ToString()!.ToLower();
        var requestedRecordTypes = new HashSet<RecordType>() { question.Type };
        var requestedRecordClass = (ResourceRecordClass)question.Class;
        if (requestedRecordTypes.Contains(RecordType.ANY))
            requestedRecordTypes.Clear();
        else if (requestedRecordTypes.Contains(RecordType.A))
            requestedRecordTypes.Add(RecordType.AAAA);
        var dbRecordTypes = requestedRecordTypes
            .Select(i => (ResourceRecordType)i)
            .ToHashSet();
        var dbNameRecord =
            await context.Set<DnsNameRecord>().FirstOrDefaultAsync(i => i.Name.ToLower() == questionDomain);
        if (dbNameRecord is null) return null;
        var resourceRecords = context.Set<DnsResourceRecord>()
            .Include(i => i.Parent)
            .Where(i => i.Parent.Id == dbNameRecord.Id)
            .Where(i => dbRecordTypes.Count == 0 || dbRecordTypes.Contains(i.RecordType))
            .Where(i => requestedRecordClass == ResourceRecordClass.Any || i.Class == requestedRecordClass)
            .AsAsyncEnumerable();

        var response = Response.FromRequest(request);

        if(await resourceRecords.ToResourceRecords(response, cancellationToken).ConfigureAwait(false))
            return response;
        return null;
    }
}

[Mapper]
public static partial class DatabaseInteropExtensions
{
    public static async Task<bool> ToResourceRecords(this IAsyncEnumerable<DnsResourceRecord> records, IResponse response, CancellationToken cancellationToken)
    {
        bool any = false;
        await foreach (var item in records.WithCancellation(cancellationToken).ConfigureAwait(false))
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