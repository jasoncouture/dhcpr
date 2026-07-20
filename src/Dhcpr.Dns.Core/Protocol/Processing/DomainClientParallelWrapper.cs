using Dhcpr.Core;
using Dhcpr.Core.Linq;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class DomainClientParallelWrapper : IDomainClient
{
    private readonly PooledList<IDomainClient> _innerClients;

    public DomainClientParallelWrapper(IEnumerable<IDomainClient> innerClients)
    {
        _innerClients = innerClients.ToPooledList();
        if (_innerClients.Count != 0)
            return;

        _innerClients.Dispose();
        throw new ArgumentException("No DNS clients provided", nameof(innerClients));
    }

    public async ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
    {
        var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var tasks = _innerClients.Select(i => i.SendAsync(message, source.Token).AsTask()).ToPooledList();
        using var exceptions = ListPool<Exception>.Default.Get();
        DomainMessage? truncatedFallback = null;

        while (tasks.Count > 0)
        {
            var completed = await Task.WhenAny(tasks);
            tasks.Remove(completed);
            try
            {
                var result = await completed;
                if (!IsAcceptableResponse(result))
                {
                    if (result.Flags.Truncated)
                        truncatedFallback ??= result;
                    continue;
                }

                CancelRemaining(tasks, source);
                return result;
            }
            catch (AggregateException ex)
            {
                foreach (var exception in ex.InnerExceptions)
                    exceptions.Add(exception);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }

        if (truncatedFallback is not null)
            return truncatedFallback;

        if (exceptions.Count == 1)
            throw new InvalidOperationException("DNS Query failed", exceptions[0]);
        if (exceptions.Count > 1)
            throw new AggregateException(exceptions);
        throw new InvalidOperationException("DNS Query failed: no usable response");
    }

    private static bool IsAcceptableResponse(DomainMessage result)
    {
        if (result.Flags.Truncated)
            return false;

        return result.Flags.ResponseCode is DomainResponseCode.NoError or DomainResponseCode.NameError;
    }

    private static void CancelRemaining(PooledList<Task<DomainMessage>> tasks, CancellationTokenSource source)
    {
        foreach (var task in tasks)
        {
            task.IgnoreExceptionsAsync().Orphan();
        }

        source.Cancel();
    }

    public void Dispose()
    {
        foreach (var client in _innerClients)
            client.Dispose();

        _innerClients.Dispose();
    }
}
