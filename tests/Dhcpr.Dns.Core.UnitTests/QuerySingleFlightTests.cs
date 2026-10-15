using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Resolvers.Caching;

namespace Dhcpr.Dns.Core.UnitTests;

public class QuerySingleFlightTests
{
    [Fact]
    public async Task Join_SharesOneResolution()
    {
        var flight = new QuerySingleFlight();
        var question = new DomainQuestion(
            new DomainLabels("netdimensional.top"),
            DomainRecordType.NS,
            DomainRecordClass.IN);
        var started = 0;
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        Task<DomainMessage> Start(CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref started);
            entered.TrySetResult();
            return release.Task.ContinueWith(
                _ => DomainMessage.CreateResponse(
                    DomainMessage.CreateRequest("netdimensional.top", DomainRecordType.NS),
                    DomainResourceRecords.Empty,
                    DomainResponseCode.ServerFailure),
                cancellationToken,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
        }

        var first = flight.JoinAsync(question, Start, CancellationToken.None).AsTask();
        await entered.Task;
        var second = flight.JoinAsync(question, Start, CancellationToken.None).AsTask();
        release.TrySetResult();

        var leader = await first;
        var follower = await second;

        Assert.Equal(1, started);
        Assert.False(leader.Shared);
        Assert.True(follower.Shared);
        Assert.Equal(DomainResponseCode.ServerFailure, follower.Message.Flags.ResponseCode);
    }
}
