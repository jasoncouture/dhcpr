using Dhcpr.Core.Linq;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class DomainClientWrapper : IDomainClient
{
    private readonly IDomainClient _left;
    private readonly IDomainClient _right;

    public DomainClientWrapper(IDomainClient left, IDomainClient right)
    {
        _left = left;
        _right = right;
    }

    public async ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
    {
        var exceptions = ListPool<Exception>.Default.Get();
        try
        {
            try
            {
                return await _left.SendAsync(message, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
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

            return await _right.SendAsync(message, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
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

        throw new AggregateException(exceptions);
    }
}