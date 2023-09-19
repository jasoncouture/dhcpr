using System.Collections.Immutable;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class CanonicalNameResolverDecorator : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _innerMiddleware;
    private readonly IDomainClientFactory _clientFactory;

    public CanonicalNameResolverDecorator(IDomainMessageMiddleware innerMiddleware, IDomainClientFactory clientFactory)
    {
        this._innerMiddleware = innerMiddleware;
        _clientFactory = clientFactory;
    }

    public async ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var result = await _innerMiddleware.ProcessAsync(context, cancellationToken);
        if (result is null)
            return result;
        result = result with { Flags = result.Flags with { RecursionAvailable = true } };
        if (!context.DomainMessage.Flags.RecursionDesired)
            return result;

        if (context.DomainMessage.Questions.All(i =>
                i.Type is not DomainRecordType.A and not DomainRecordType.AAAA and not DomainRecordType.CNAME))
            return result;

        if (result.Records.All(i => i.Type != DomainRecordType.CNAME))
            return result;

        if (result.Records.Answers.Any(i =>
                i.Type != DomainRecordType.CNAME && i.Type == context.DomainMessage.Questions[0].Type))
            return result;

        var cnameRecords = result.Records
            .Where(i => i.Type == DomainRecordType.CNAME)
            .ToPooledList();

        var internalClient =
            await _clientFactory.GetDomainClient(new DomainClientOptions() { Type = DomainClientType.Internal },
                cancellationToken);

        foreach (var (record, type) in cnameRecords.SelectMany(i => new[]
                 {
                     (record: i, DomainRecordType.A), (record: i, DomainRecordType.AAAA)
                 }))
        {
            var nextRequest = DomainMessage.CreateRequest(((NameData)record.Data).Name.ToString(), type);

            var nextResponse = await internalClient.SendAsync(nextRequest, cancellationToken)
                .AsTask()
                .ConvertExceptionsToNull();

            if (nextResponse is null) continue;
            if (nextResponse.Records.Answers.Length == 0) continue;

            result = result with
            {
                Records = result.Records with
                {
                    Additional = result.Records.Additional
                        .Concat(
                            nextResponse.Records.Where(i => i.Type == type)
                        )
                        .ToImmutableArray()
                }
            };
        }

        return result;
    }

    public string Name => _innerMiddleware.Name;

    public int Priority => _innerMiddleware.Priority;
}