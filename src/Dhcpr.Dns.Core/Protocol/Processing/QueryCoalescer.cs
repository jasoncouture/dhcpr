using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Query-scoped single-flight for identical internal hops. Directed NS/DS
/// probes bypass the response cache, so four parallel glue walks otherwise
/// each re-ask the same parent cut.
/// </summary>
public sealed class QueryCoalescer
{
    private readonly ConcurrentDictionary<string, Task<DomainMessage>> _inflight =
        new(StringComparer.Ordinal);

    public async ValueTask<DomainMessage> JoinAsync(
        DomainQuestion question,
        ImmutableArray<IPEndPoint> endpoints,
        Func<CancellationToken, Task<DomainMessage>> start,
        CancellationToken cancellationToken)
    {
        var key = Key(question, endpoints);
        while (true)
        {
            if (_inflight.TryGetValue(key, out var existing))
                return await existing.WaitAsync(cancellationToken).ConfigureAwait(false);

            var tcs = new TaskCompletionSource<DomainMessage>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            if (!_inflight.TryAdd(key, tcs.Task))
                continue;

            try
            {
                var result = await start(cancellationToken).ConfigureAwait(false);
                tcs.TrySetResult(result);
                return result;
            }
            catch (OperationCanceledException)
            {
                tcs.TrySetCanceled(cancellationToken);
                throw;
            }
            catch (Exception ex)
            {
                tcs.TrySetException(ex);
                throw;
            }
            finally
            {
                _inflight.TryRemove(key, out _);
            }
        }
    }

    private static string Key(DomainQuestion question, ImmutableArray<IPEndPoint> endpoints)
    {
        if (endpoints.IsDefaultOrEmpty)
            return $"{question.Class:D}/{question.Type:D}/{question.Name}";

        return $"{question.Class:D}/{question.Type:D}/{question.Name}/{string.Join(",", endpoints.Select(static e => e.ToString()).Order(StringComparer.Ordinal))}";
    }
}
