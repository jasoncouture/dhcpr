﻿namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed record InternalDnsRequestReceivedMessage(DomainMessageContext Context,
    TaskCompletionSource<DomainMessage?> TaskCompletionSource) : DnsPacketReceivedMessage(Context)
{
    public InternalDnsRequestReceivedMessage(DomainMessageContext context) : this(context,
        new TaskCompletionSource<DomainMessage?>())
    {
    }

    protected override void Dispose(bool disposing)
    {
        TaskCompletionSource.TrySetResult(null);
    }
}