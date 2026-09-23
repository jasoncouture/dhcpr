using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

/// <summary>
/// Fetches a fresh response and stores it. The caller supplies the scope.
/// </summary>
public sealed partial class DnsCacheRefresh : IDnsCacheRefresh
{
    internal static readonly TimeSpan RefreshTimeout = TimeSpan.FromSeconds(10);

    private readonly IInternalDomainClient _client;
    private readonly IDnsResponseCache _cache;
    private readonly IDnsCacheRefreshTracker _inFlight;
    private readonly ILogger<DnsCacheRefresh> _logger;

    public DnsCacheRefresh(
        IInternalDomainClient client,
        IDnsResponseCache cache,
        IDnsCacheRefreshTracker inFlight,
        ILogger<DnsCacheRefresh> logger)
    {
        _client = client;
        _cache = cache;
        _inFlight = inFlight;
        _logger = logger;
    }

    public async Task RefreshAsync(DomainMessageContext parent)
    {
        if (parent.DomainMessage.Questions.Length != 1)
            return;

        var question = parent.DomainMessage.Questions[0];
        var key = DnsCacheKey.FromQuestion(question);
        if (!_inFlight.TryAdd(key))
            return;

        try
        {
            LogRefresh(_logger, question.Name, question.Type);
            using var timeout = new CancellationTokenSource(RefreshTimeout);
            var request = DomainMessage.CreateRequest(question.Name, question.Type, question.Class);
            var fresh = await _client
                .SendRefreshAsync(parent, request, timeout.Token)
                .ConfigureAwait(false);
            _cache.Set(request, fresh.Message, fresh.SecurityStatus);
        }
        finally
        {
            _inFlight.Remove(key);
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Refresh {Name} {Type}")]
    private static partial void LogRefresh(ILogger logger, DomainLabels name, DomainRecordType type);
}
