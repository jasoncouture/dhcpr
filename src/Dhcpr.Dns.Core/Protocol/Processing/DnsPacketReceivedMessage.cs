namespace Dhcpr.Dns.Core.Protocol.Processing;

public abstract record DnsPacketReceivedMessage(DomainMessageContext Context) : IDisposable
{
    protected virtual void Dispose(bool disposing)
    {

    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }
}