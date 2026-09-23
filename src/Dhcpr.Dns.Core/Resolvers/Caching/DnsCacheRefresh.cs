using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

/// <summary>
/// Refreshes a hot cache entry on its own scope so the query scope can end
/// while the upstream fetch is still running.
/// </summary>
public sealed partial class DnsCacheRefresh : IDnsCacheRefresh
{
    internal static readonly TimeSpan RefreshTimeout = TimeSpan.FromSeconds(10);

    private readonly IServiceScopeFactory _scopes;
    private readonly IDnsResponseCache _cache;
    private readonly IDnsCacheRefreshTracker _inFlight;
    private readonly ILogger<DnsCacheRefresh> _logger;

    public DnsCacheRefresh(
        IServiceScopeFactory scopes,
        IDnsResponseCache cache,
        IDnsCacheRefreshTracker inFlight,
        ILogger<DnsCacheRefresh> logger)
    {
        _scopes = scopes;
        _cache = cache;
        _inFlight = inFlight;
        _logger = logger;
    }

    public void Schedule(DomainMessageContext context)
    {
        if (context.DomainMessage.Questions.Length != 1)
            return;

        var question = context.DomainMessage.Questions[0];
        var key = DnsCacheKey.FromQuestion(question);
        if (!_inFlight.TryAdd(key))
            return;

        RefreshAsync(context, question, key);
    }

    private async void RefreshAsync(
        DomainMessageContext parent,
        DomainQuestion question,
        DnsCacheKey key)
    {
        try
        {
            await Task.Yield();
            LogRefresh(_logger, question.Name, question.Type);
            await using var scope = _scopes.CreateAsyncScope();
            var client = scope.ServiceProvider.GetRequiredService<IInternalDomainClient>();
            using var timeout = new CancellationTokenSource(RefreshTimeout);
            var request = DomainMessage.CreateRequest(question.Name, question.Type, question.Class);
            var fresh = await client
                .SendRefreshAsync(parent, request, timeout.Token)
                .ConfigureAwait(false);
            _cache.Set(request, fresh.Message, fresh.SecurityStatus);
        }
        catch (Exception exception)
        {
            LogRefreshFailed(_logger, exception, question.Name, question.Type);
        }
        finally
        {
            _inFlight.Remove(key);
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Refresh {Name} {Type}")]
    private static partial void LogRefresh(ILogger logger, DomainLabels name, DomainRecordType type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Refresh {Name} {Type} failed")]
    private static partial void LogRefreshFailed(
        ILogger logger,
        Exception exception,
        DomainLabels name,
        DomainRecordType type);
}
