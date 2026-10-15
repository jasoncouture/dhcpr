using System.Collections.Concurrent;

using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public readonly record struct SingleFlightJoin(DomainMessage Message, bool Shared);

/// <summary>
/// One in-flight resolution per question for the process. A burst of the same
/// name waits on the first walk instead of each packet repeating it.
/// </summary>
public interface IQuerySingleFlight
{
    ValueTask<SingleFlightJoin> JoinAsync(
        DomainQuestion question,
        Func<CancellationToken, Task<DomainMessage>> start,
        CancellationToken cancellationToken);
}

public sealed class QuerySingleFlight : IQuerySingleFlight
{
    private readonly ConcurrentDictionary<string, Task<DomainMessage>> _inflight =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly AsyncLocal<bool> _inside = new();

    public async ValueTask<SingleFlightJoin> JoinAsync(
        DomainQuestion question,
        Func<CancellationToken, Task<DomainMessage>> start,
        CancellationToken cancellationToken)
    {
        // A chase re-enters the pipeline on this flow. Joining again deadlocks.
        if (_inside.Value)
            return new SingleFlightJoin(await start(cancellationToken).ConfigureAwait(false), false);

        var key = $"{question.Class:D}/{question.Type:D}/{question.Name}";
        while (true)
        {
            if (_inflight.TryGetValue(key, out var existing))
            {
                var shared = await existing.WaitAsync(cancellationToken).ConfigureAwait(false);
                return new SingleFlightJoin(shared, true);
            }

            var pending = new TaskCompletionSource<DomainMessage>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            if (!_inflight.TryAdd(key, pending.Task))
                continue;

            _inside.Value = true;
            try
            {
                var result = await start(cancellationToken).ConfigureAwait(false);
                pending.TrySetResult(result);
                return new SingleFlightJoin(result, false);
            }
            catch (OperationCanceledException)
            {
                pending.TrySetCanceled(cancellationToken);
                throw;
            }
            catch (Exception ex)
            {
                pending.TrySetException(ex);
                throw;
            }
            finally
            {
                _inside.Value = false;
                _inflight.TryRemove(key, out _);
            }
        }
    }
}
