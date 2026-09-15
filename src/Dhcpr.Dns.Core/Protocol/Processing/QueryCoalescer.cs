using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Text;

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
        string key,
        Func<CancellationToken, Task<DomainMessage>> start,
        CancellationToken cancellationToken)
    {
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

    public static string Key(DomainMessage message, ImmutableArray<IPEndPoint> endpoints)
    {
        var question = message.Questions[0];
        var builder = new StringBuilder();
        builder.Append((int)question.Class);
        builder.Append('/');
        builder.Append((int)question.Type);
        builder.Append('/');
        builder.Append(question.Name);
        if (endpoints.IsDefaultOrEmpty)
            return builder.ToString();

        builder.Append('/');
        var ordered = endpoints
            .Select(static e => e.ToString())
            .Order(StringComparer.Ordinal);
        var first = true;
        foreach (var endpoint in ordered)
        {
            if (!first)
                builder.Append(',');
            builder.Append(endpoint);
            first = false;
        }

        return builder.ToString();
    }
}
