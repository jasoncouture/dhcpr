using System.Net;
using System.Text;

using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed partial class QueryLoggingDomainMessageMiddleware : IDomainMessageMiddleware
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
        var isServFail = result.Flags.ResponseCode is DomainResponseCode.ServerFailure;
        foreach (var question in context.DomainMessage.Questions)
        {
            if (isServFail)
            {
                LogServFail(
                    _logger,
                    queryId,
                    context.ClientEndPoint,
                    context.ServerEndPoint,
                    question.Type,
                    question.Name,
                    context.ServFailReason ?? "unspecified",
                    hitString);
                continue;
            }

            var addresses = FormatAnswerAddresses(result, question.Type);
            LogQueryResponse(
                _logger,
                hitString,
                queryId,
                context.ClientEndPoint,
                context.ServerEndPoint,
                question.Type,
                question.Name,
                addresses);
        }
    }

    private void LogQuery(DomainMessageContext context, Guid queryId)
    {
        foreach (var question in context.DomainMessage.Questions)
        {
            LogIncomingQuery(
                _logger,
                queryId,
                context.ClientEndPoint,
                context.ServerEndPoint,
                question.Type,
                question.Name);
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

    [LoggerMessage(Level = LogLevel.Error, Message = "SERVFAIL [{QueryId:n}] {Client} <- {Server}: {QueryType} {Name} reason={Reason} cache={CacheState}")]
    private static partial void LogServFail(
        ILogger logger,
        Guid queryId,
        IPEndPoint? client,
        IPEndPoint? server,
        DomainRecordType queryType,
        DomainLabels name,
        string reason,
        string cacheState);

    [LoggerMessage(Level = LogLevel.Information, Message = "{CacheState} [{QueryId:n}] {Client} <- {Server}: {QueryType} {Name} {Answers}")]
    private static partial void LogQueryResponse(
        ILogger logger,
        string cacheState,
        Guid queryId,
        IPEndPoint? client,
        IPEndPoint? server,
        DomainRecordType queryType,
        DomainLabels name,
        string answers);

    [LoggerMessage(Level = LogLevel.Debug, Message = "[{QueryId:n}] {Client} -> {Server}: {QueryType} {Name}")]
    private static partial void LogIncomingQuery(
        ILogger logger,
        Guid queryId,
        IPEndPoint? client,
        IPEndPoint? server,
        DomainRecordType queryType,
        DomainLabels name);
}
