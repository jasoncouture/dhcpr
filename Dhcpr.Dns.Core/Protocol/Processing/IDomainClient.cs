namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainClient : IDisposable
{
    ValueTask<DomainMessage> SendAsync(DomainMessage message,
        CancellationToken cancellationToken);

    void IDisposable.Dispose()
    {
        // ReSharper disable once GCSuppressFinalizeForTypeWithoutDestructor
        GC.SuppressFinalize(this);
    }
}