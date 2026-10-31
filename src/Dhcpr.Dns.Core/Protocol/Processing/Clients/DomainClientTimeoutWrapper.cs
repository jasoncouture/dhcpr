namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class DomainClientTimeoutWrapper : IDomainClient
{
    private readonly IDomainClient _implementation;
    private readonly TimeSpan _timeout;

    public DomainClientTimeoutWrapper(IDomainClient implementation, TimeSpan timeout)
    {
        _implementation = implementation;
        _timeout = timeout;
    }

    public void Dispose() => _implementation.Dispose();

    public async ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
    {
        using var timeoutTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutTokenSource.CancelAfter(_timeout);
        return await _implementation.SendAsync(message, timeoutTokenSource.Token);
    }
}