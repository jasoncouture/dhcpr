using Dhcpr.Data;
using Dhcpr.Data.Dns.Models;
using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Protocol;

using Microsoft.EntityFrameworkCore;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Database;

public sealed class DatabaseResolver : IDatabaseResolver
{
    private readonly IDataContext _dataContext;

    public DatabaseResolver(IDataContext dataContext)
    {
        _dataContext = dataContext;
    }

    public async Task<IResponse?> Resolve(IRequest request, CancellationToken cancellationToken = default)
    {
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
            await _dataContext.NameRecords.FirstOrDefaultAsync(i => i.Name.ToLower() == questionDomain, cancellationToken: cancellationToken)
                ;
        
        if (dbNameRecord is null) 
            return null;

        var response = Response.FromRequest(request);
        
        var resourceRecords = _dataContext.ResourceRecords
            .Include(i => i.Parent)
            .Where(i => i.Parent.Id == dbNameRecord.Id)
            .Where(i => dbRecordTypes.Count == 0 || dbRecordTypes.Contains(i.RecordType))
            .Where(i => requestedRecordClass == ResourceRecordClass.Any || i.Class == requestedRecordClass)
            .AsAsyncEnumerable();

        if(await resourceRecords.ToResourceRecords(response, cancellationToken))
            return new NoCacheResponse(response);
        
        return null;
    }
}