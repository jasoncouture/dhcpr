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
        DomainMessage? nameErrorFallback = null;

        while (tasks.Count > 0)
        {
            var completed = await Task.WhenAny(tasks);
            tasks.Remove(completed);
            try
            {
                var result = await completed;
                if (result.Flags.Truncated)
                {
                    truncatedFallback ??= result;
                    continue;
                }

                // Only NOERROR wins immediately. NXDOMAIN must wait for the rest of the race —
                // a lame/unreachable peer timing out must not let a single NXDOMAIN win.
                if (result.Flags.ResponseCode is DomainResponseCode.NoError)
                {
                    CancelRemaining(tasks, source);
                    return result;
                }

                if (result.Flags.ResponseCode is DomainResponseCode.NameError)
                    nameErrorFallback ??= result;
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

        // Transport failures in the batch: do not promote a raced NXDOMAIN to a final answer.
        if (exceptions.Count == 1 && NameserverSelection.IsTransportFailure(exceptions[0]))
            throw new InvalidOperationException("DNS Query failed", exceptions[0]);
        if (exceptions.Count > 1 && exceptions.All(NameserverSelection.IsTransportFailure))
            throw new AggregateException(exceptions);

        if (nameErrorFallback is not null && exceptions.Count == 0)
            return nameErrorFallback;

        // Prefer a SERVFAIL response over throwing — callers can try more nameservers.
        return DomainMessage.CreateResponse(
            message,
            DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure);
    }

    private static void CancelRemaining(PooledList<Task<DomainMessage>> tasks, CancellationTokenSource source)
    {
        foreach (var task in tasks)
        {
            task.IgnoreExceptionsAsync().OrphanAsync();
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
