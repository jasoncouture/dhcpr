using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// REFUSED when the query carries this resolver's loop tag. Outside the
/// cache so the packet does not join the in-flight lookup it is the reply to.
/// </summary>
public sealed partial class LoopQueryMiddleware : IDomainMessageMiddleware
{
    private static readonly TimeSpan _refusedTtl = TimeSpan.FromDays(1);
    private static readonly DomainLabels _masterName = new("localhost");
    private static readonly DomainLabels _responsibleName = new("nobody.invalid");
    private readonly IDomainMessageMiddleware _inner;
    private readonly IEdnsLoopTag _loopTag;
    private readonly ILogger<LoopQueryMiddleware> _logger;

    public LoopQueryMiddleware(
        IDomainMessageMiddleware inner,
        IEdnsLoopTag loopTag,
        ILogger<LoopQueryMiddleware> logger)
    {
        _inner = inner;
        _loopTag = loopTag;
        _logger = logger;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (!_loopTag.IsOurs(context.DomainMessage))
            return await _inner.ProcessAsync(context, cancellationToken).ConfigureAwait(false);

        var question = context.DomainMessage.Questions is [{ } looped, ..] ? looped : null;
        context.AnsweredBy = "Loop";
        if (question is not null)
            LogLoopedQuery(_logger, context.ClientEndPoint, question.Type, question.Name);

        return DomainMessage.CreateResponse(
            context.DomainMessage,
            authorities: question is null ? null : [RefusalSoa(question)],
            additional: [EdnsExtendedError.Create(EdnsExtendedError.Other, EdnsExtendedError.LoopDetectedText)],
            responseCode: DomainResponseCode.Refused);
    }

    private static DomainResourceRecord RefusalSoa(DomainQuestion question)
        => new(
            question.Name,
            DomainRecordType.SOA,
            question.Class,
            _refusedTtl,
            new StartOfAuthorityData(
                _masterName,
                _responsibleName,
                1,
                TimeSpan.FromHours(1),
                TimeSpan.FromMinutes(20),
                TimeSpan.FromDays(7),
                _refusedTtl));

    [LoggerMessage(
        Level = LogLevel.Debug,
        Message = "Looped query {Name}/{QueryType} from {Client}")]
    private static partial void LogLoopedQuery(
        ILogger logger,
        IPEndPoint? client,
        DomainRecordType queryType,
        DomainLabels name);
}
