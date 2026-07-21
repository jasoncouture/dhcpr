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
        var result = await _inner.ProcessAsync(context, cancellationToken);
        if (result is null || IsInternalRequest(context))
            return result;

        foreach (var question in context.DomainMessage.Questions)
        {
            _logger.LogInformation("{QueryType} {Name}", question.Type, question.Name);

            if (question.Type is not (DomainRecordType.A or DomainRecordType.AAAA))
                continue;

            var addresses = FormatAnswerAddresses(result, question.Type);
            if (addresses.Length > 0)
                _logger.LogInformation("{Addresses}", addresses);
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
