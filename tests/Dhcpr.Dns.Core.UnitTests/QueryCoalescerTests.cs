using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class QueryCoalescerTests
{
    [Fact]
    public void Key_IgnoresEndpointOrder()
    {
        var message = DomainMessage.CreateRequest("ntpns.org", DomainRecordType.NS);
        var a = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53);
        var b = new IPEndPoint(IPAddress.Parse("192.0.2.2"), 53);

        var left = QueryCoalescer.Key(message, ImmutableArray.Create(a, b));
        var right = QueryCoalescer.Key(message, ImmutableArray.Create(b, a));

        Assert.Equal(left, right);
    }

    [Fact]
    public async Task JoinAsync_CancelledWaiterDoesNotCancelWinner()
    {
        var coalescer = new QueryCoalescer();
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = DomainMessage.CreateResponse(
            DomainMessage.CreateRequest("ntpns.org", DomainRecordType.NS),
            DomainResourceRecords.Empty,
            DomainResponseCode.NoError);

        using var waiterCts = new CancellationTokenSource();

        var winner = coalescer.JoinAsync(
            "k",
            async _ =>
            {
                started.SetResult();
                await release.Task;
                return response;
            },
            CancellationToken.None).AsTask();

        await started.Task;
        var waiter = coalescer.JoinAsync("k", _ => Task.FromResult(response), waiterCts.Token).AsTask();
        await waiterCts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiter);
        Assert.False(winner.IsCompleted);

        release.SetResult();
        Assert.Same(response, await winner);
    }
}
