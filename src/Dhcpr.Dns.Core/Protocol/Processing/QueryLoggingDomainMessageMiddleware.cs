using System.Net;
using System.Text;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class QueryLoggingDomainMessageMiddleware : IDomainMessageMiddleware
{
    private static readonly IPAddress InternalAddress = IPAddress.Any;

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
        var queryId = Guid.CreateVersion7();
        foreach (var question in context.DomainMessage.Questions)
        {
            if (question.Type is not (DomainRecordType.A or DomainRecordType.AAAA))
                continue;

            _logger.LogDebug("[{QueryId:n}] {Client} -> {Server}: {QueryType} {Name}",
                context.ClientEndPoint,
                context.ServerEndPoint,
                queryId,
                question.Type,
                question.Name.ToString()
            );
        }

        var result = await _inner.ProcessAsync(context, cancellationToken);

        if (result is null)
            return result;

        foreach (var question in context.DomainMessage.Questions)
        {
            var addresses = FormatAnswerAddresses(result, question.Type);
            if (addresses.Length > 0)
                _logger.LogInformation("[{QueryId:n}] {Client} <- {Server}: {QueryType} {Name} {Answers}",
                    context.ClientEndPoint,
                    context.ServerEndPoint,
                    queryId,
                    question.Type,
                    question.Name.ToString(),
                    addresses
                );
        }

        return result;
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

    private static bool IsInternalRequest(DomainMessageContext context) =>
        context.ClientEndPoint is { Port: 53 } endpoint &&
        endpoint.Address.Equals(InternalAddress);
}