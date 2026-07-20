namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Sends via UDP first; if the response is truncated, retries the same query over TCP.
/// </summary>
public sealed class DomainClientTruncationFallbackWrapper : IDomainClient
{
    private readonly IDomainClient _udpClient;
    private readonly IDomainClient _tcpClient;

    public DomainClientTruncationFallbackWrapper(IDomainClient udpClient, IDomainClient tcpClient)
    {
        _udpClient = udpClient;
        _tcpClient = tcpClient;
    }

    public async ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
    {
        var result = await _udpClient.SendAsync(message, cancellationToken);
        if (!result.Flags.Truncated)
            return result;

        return await _tcpClient.SendAsync(message, cancellationToken);
    }

    public void Dispose()
    {
        _udpClient.Dispose();
        _tcpClient.Dispose();
    }
}
