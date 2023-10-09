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

        while (tasks.Count > 0)
        {
            var completed = await Task.WhenAny(tasks);
            tasks.Remove(completed);
            try
            {
                var result = await completed;
                // Orphan the remaining tasks.
                foreach (var task in tasks)
                {
                    task.IgnoreExceptionsAsync().Orphan();
                }

                source.Cancel();
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

        if (exceptions.Count == 1)
            throw new InvalidOperationException("DNS Query failed", exceptions[0]);
        throw new AggregateException(exceptions);
    }

    public void Dispose()
    {
        foreach (var client in _innerClients)
            client.Dispose();

        _innerClients.Dispose();
    }
}