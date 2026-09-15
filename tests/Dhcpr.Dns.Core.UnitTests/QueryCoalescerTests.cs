using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class QueryCoalescerTests
{
    [Fact]
    public async Task JoinAsync_IgnoresEndpointOrder()
    {
        var coalescer = new QueryCoalescer();
        var message = DomainMessage.CreateRequest("ntpns.org", DomainRecordType.NS);
        var a = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53);
        var b = new IPEndPoint(IPAddress.Parse("192.0.2.2"), 53);
        var started = 0;
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = DomainMessage.CreateResponse(
            message,
            DomainResourceRecords.Empty,
            DomainResponseCode.NoError);

        Task<DomainMessage> Start(CancellationToken _)
        {
            Interlocked.Increment(ref started);
            return WaitForReleaseAsync();
        }

        async Task<DomainMessage> WaitForReleaseAsync()
        {
            await release.Task;
            return response;
        }

        var first = coalescer.JoinAsync(
            message.Questions[0],
            ImmutableArray.Create(a, b),
            Start,
            CancellationToken.None).AsTask();
        var second = coalescer.JoinAsync(
            message.Questions[0],
            ImmutableArray.Create(b, a),
            Start,
            CancellationToken.None).AsTask();

        while (Volatile.Read(ref started) == 0)
            await Task.Yield();

        Assert.Equal(1, started);
        release.SetResult();
        Assert.Same(response, await first);
        Assert.Same(response, await second);
        Assert.Equal(1, started);
    }

    [Fact]
    public async Task JoinAsync_CancelledWaiterDoesNotCancelWinner()
    {
        var coalescer = new QueryCoalescer();
        var request = DomainMessage.CreateRequest("ntpns.org", DomainRecordType.NS);
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = DomainMessage.CreateResponse(
            request,
            DomainResourceRecords.Empty,
            DomainResponseCode.NoError);

        using var waiterCts = new CancellationTokenSource();

        var winner = coalescer.JoinAsync(
            request.Questions[0],
            endpoints: default,
            async _ =>
            {
                started.SetResult();
                await release.Task;
                return response;
            },
            CancellationToken.None).AsTask();

        await started.Task;
        var waiter = coalescer.JoinAsync(
            request.Questions[0],
            endpoints: default,
            _ => Task.FromResult(response),
            waiterCts.Token).AsTask();
        await waiterCts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiter);
        Assert.False(winner.IsCompleted);

        release.SetResult();
        Assert.Same(response, await winner);
    }
}
