namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainClient : IDisposable
{
    /// <summary>
    /// Sends <paramref name="message"/> and returns the response.
    /// </summary>
    ValueTask<DomainMessage> SendAsync(DomainMessage message,
        CancellationToken cancellationToken);

    /// <summary>
    /// Releases resources. The default implementation is a no-op besides suppressing finalization.
    /// </summary>
    void IDisposable.Dispose()
    {
        // ReSharper disable once GCSuppressFinalizeForTypeWithoutDestructor
        GC.SuppressFinalize(this);
    }
}