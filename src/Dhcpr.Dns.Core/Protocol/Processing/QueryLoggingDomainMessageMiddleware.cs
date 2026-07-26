using System.Text;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class QueryLoggingDomainMessageMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;
    private readonly ILogger<QueryLoggingDomainMessageMiddleware> _logger;

    public QueryLoggingDomainMessageMiddleware(
        IDomainMessageMiddleware inner,
        ILogger<QueryLoggingDomainMessageMiddleware> logger)
    {
        _inner = inner;
        _logger = logger;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var result = await _inner.ProcessAsync(context, cancellationToken);

        if (result is null || context.IsInternal)
            return result;

        var queryId = Guid.CreateVersion7();
        LogResponse(context, result, queryId);

        return result;
    }

    private void LogResponse(DomainMessageContext context, DomainMessage result, Guid queryId)
    {
        var hitString = context.CacheHit ? "HIT" : "MISS";
        foreach (var question in context.DomainMessage.Questions)
        {
            var addresses = FormatAnswerAddresses(result, question.Type);
            _logger.LogInformation("{CacheState} [{QueryId:n}] {Client} <- {Server}: {QueryType} {Name} {Answers}",
                hitString,
                queryId,
                context.ClientEndPoint,
                context.ServerEndPoint,
                question.Type,
                question.Name.ToString(),
                addresses
            );
        }
    }

    private void LogQuery(DomainMessageContext context, Guid queryId)
    {
        foreach (var question in context.DomainMessage.Questions)
        {
            _logger.LogDebug("[{QueryId:n}] {Client} -> {Server}: {QueryType} {Name}",
                queryId,
                context.ClientEndPoint,
                context.ServerEndPoint,
                question.Type,
                question.Name.ToString()
            );
        }
    }

    private static string FormatAnswerAddresses(DomainMessage response, DomainRecordType type)
    {
        var builder = new StringBuilder();
        foreach (var record in response.Records.Answers)
        {
            if (record.Type != type || record.Data is not IPAddressData addressData)
                continue;

            if (builder.Length > 0)
                builder.Append(',');
            builder.Append(addressData.Address);
        }

        return builder.ToString();
    }
}
