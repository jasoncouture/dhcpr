using System.Net;
using System.Text;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface ICacheState
{
    bool CacheHit { get; }
}

public sealed class CacheState : ICacheState
{
    private readonly AsyncLocal<bool?> _cacheHit = new AsyncLocal<bool?>();

    public bool CacheHit
    {
        get => _cacheHit.Value ??= false;
        set => _cacheHit.Value = value;
    }
}
public sealed class QueryLoggingDomainMessageMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;
    private readonly ICacheState _cacheState;
    private readonly ILogger<QueryLoggingDomainMessageMiddleware> _logger;

    public QueryLoggingDomainMessageMiddleware(
        IDomainMessageMiddleware inner,
        ICacheState cacheState,
        ILogger<QueryLoggingDomainMessageMiddleware> logger)
    {
        _inner = inner;
        _cacheState = cacheState;
        _logger = logger;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var queryId = Guid.CreateVersion7();
        LogQuery(context, queryId);
        var result = await _inner.ProcessAsync(context, cancellationToken);

        if (result is not null)
            LogResponse(context, result, queryId);

        return result;
    }

    private void LogResponse(DomainMessageContext context, DomainMessage result, Guid queryId)
    {
        var hitString = _cacheState.CacheHit ? "HIT" : "MISS";
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