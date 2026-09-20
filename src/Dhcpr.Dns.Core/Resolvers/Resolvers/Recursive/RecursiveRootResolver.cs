using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.RootZone;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed partial class RecursiveRootResolver : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;
    private readonly ILogger<RecursiveRootResolver> _logger;
    private readonly IReferralWalker _referralWalker;
    private readonly IRootServerTips _rootServerTips;

    public RecursiveRootResolver(
        IDomainMessageMiddleware inner,
        IRootServerTips rootServerTips,
        IReferralWalker referralWalker,
        ILogger<RecursiveRootResolver> logger
    )
    {
        _inner = inner;
        _rootServerTips = rootServerTips;
        _referralWalker = referralWalker;
        _logger = logger;
    }

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        // Directed upstream hops are owned by UpstreamQueryMiddleware.
        if (context.UpstreamEndpoints is { Length: > 0 })
            return await _inner.ProcessAsync(context, cancellationToken).ConfigureAwait(false);

        var question = context.DomainMessage.Questions[0];
        using var startPoints = ListPool<IPEndPoint>.Default.Get();
        if (context.NameserverTips is { } tips &&
            tips.TryGetClosest(question.Name, question.Type, out var cachedTips, out _))
        {
            startPoints.AddRange(cachedTips);
        }
        else
        {
            startPoints.AddRange(_rootServerTips.GetEndpoints().OrderBy(_ => Random.Shared.Next()));
        }

        try
        {
            var cloned = context.DomainMessage with { Id = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1) };
            var result = await _referralWalker.FollowAsync(
                context, cloned, startPoints, cancellationToken);

            if (result.Records.Answers.Length == 0 &&
                cloned.Questions[0].Type is DomainRecordType.A or DomainRecordType.AAAA)
            {
                result = await RecursiveCnameFallback.TryQueryAsync(
                    context, cloned, result, startPoints, _referralWalker, cancellationToken);
            }

            context.AnsweredBy ??= Name;
            return RecursiveResponseNormalizer.FinalizeRecursiveResponse(context.DomainMessage, result);
        }
        catch (Exception ex)
        {
            if (!cancellationToken.IsCancellationRequested)
            {
                LogUnhandledException(_logger, ex);
            }

            context.ServFailReason = "recursive resolver exception";
            context.AnsweredBy ??= Name;
            return DomainMessage.CreateResponse(context.DomainMessage, DomainResourceRecords.Empty,
                DomainResponseCode.ServerFailure);
        }
    }

    public string Name { get; } = "Recursive Resolver";
    public int Priority { get; } = 5000;

    [LoggerMessage(Level = LogLevel.Error, Message = "An unhandled exception occurred while resolving recursively.")]
    private static partial void LogUnhandledException(ILogger logger, Exception exception);
}
