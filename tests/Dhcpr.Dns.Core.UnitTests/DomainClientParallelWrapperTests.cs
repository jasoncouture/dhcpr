using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DomainClientParallelWrapperTests
{
    [Fact]
    public async Task AllUnacceptableResponsesReturnServerFailure()
    {
        var failure = CreateResponse(DomainResponseCode.ServerFailure, truncated: false);
        using var wrapper = new DomainClientParallelWrapper(new IDomainClient[]
        {
            DelayedClient(failure, TimeSpan.Zero),
            DelayedClient(failure, TimeSpan.Zero)
        });

        var result = await wrapper.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None);
        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
    }

    [Fact]
    public async Task PrefersNoErrorOverServerFailure()
    {
        var failure = CreateResponse(DomainResponseCode.ServerFailure, truncated: false);
        var success = CreateResponse(DomainResponseCode.NoError, truncated: false);

        // Slow success, fast failure — wrapper must wait for an acceptable response.
        using var wrapper = new DomainClientParallelWrapper(new IDomainClient[]
        {
            DelayedClient(failure, TimeSpan.FromMilliseconds(10)),
            DelayedClient(success, TimeSpan.FromMilliseconds(50))
        });

        var result = await wrapper.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None);
        Assert.Equal(DomainResponseCode.NoError, result.Flags.ResponseCode);
    }

    [Fact]
    public async Task PrefersNoErrorOverFasterNameError()
    {
        var nameError = CreateResponse(DomainResponseCode.NameError, truncated: false);
        var success = CreateResponse(DomainResponseCode.NoError, truncated: false);

        using var wrapper = new DomainClientParallelWrapper(new IDomainClient[]
        {
            DelayedClient(nameError, TimeSpan.FromMilliseconds(10)),
            DelayedClient(success, TimeSpan.FromMilliseconds(50))
        });

        var result = await wrapper.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None);
        Assert.Equal(DomainResponseCode.NoError, result.Flags.ResponseCode);
    }

    [Fact]
    public async Task NameErrorWithPeerTransportFailureDoesNotReturnNameError()
    {
        var nameError = CreateResponse(DomainResponseCode.NameError, truncated: false);

        using var wrapper = new DomainClientParallelWrapper(new IDomainClient[]
        {
            DelayedClient(nameError, TimeSpan.FromMilliseconds(10)),
            ThrowingClient(new IOException("timed out"))
        });

        await Assert.ThrowsAnyAsync<Exception>(async () =>
            await wrapper.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None));
    }

    [Fact]
    public async Task AllNameErrorResponsesReturnNameError()
    {
        var nameError = CreateResponse(DomainResponseCode.NameError, truncated: false);

        using var wrapper = new DomainClientParallelWrapper(new IDomainClient[]
        {
            DelayedClient(nameError, TimeSpan.Zero),
            DelayedClient(nameError, TimeSpan.Zero)
        });

        var result = await wrapper.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None);
        Assert.Equal(DomainResponseCode.NameError, result.Flags.ResponseCode);
    }

    [Fact]
    public async Task SkipsTruncatedResponsesWhenBetterResponseExists()
    {
        var truncated = CreateResponse(DomainResponseCode.NoError, truncated: true);
        var complete = CreateResponse(DomainResponseCode.NoError, truncated: false);

        using var wrapper = new DomainClientParallelWrapper(new IDomainClient[]
        {
            DelayedClient(truncated, TimeSpan.FromMilliseconds(10)),
            DelayedClient(complete, TimeSpan.FromMilliseconds(40))
        });

        var result = await wrapper.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None);
        Assert.False(result.Flags.Truncated);
    }

    [Fact]
    public async Task TimeoutWrapperCancelsViaLinkedToken()
    {
        var sawCancellation = false;
        var inner = Substitute.For<IDomainClient>();
        inner.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(ci => ObserveCancellation(
                ci.Arg<DomainMessage>(),
                ci.Arg<CancellationToken>(),
                cancelled => sawCancellation = cancelled));
        using var wrapper = new DomainClientTimeoutWrapper(inner, TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await wrapper.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None));

        Assert.True(sawCancellation);
    }

    [Fact]
    public async Task TruncationFallbackRetriesOverTcp()
    {
        var udp = FixedClient(CreateResponse(DomainResponseCode.NoError, truncated: true));
        var tcp = FixedClient(CreateResponse(DomainResponseCode.NoError, truncated: false));
        using var wrapper = new DomainClientTruncationFallbackWrapper(udp, tcp);

        var result = await wrapper.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None);

        Assert.False(result.Flags.Truncated);
        await udp.Received(1).SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>());
        await tcp.Received(1).SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>());
    }

    private static DomainMessage CreateResponse(DomainResponseCode code, bool truncated)
    {
        var request = DomainMessage.CreateRequest("example.com");
        return new DomainMessage(
            request.Id,
            request.Flags with { Response = true, Truncated = truncated, ResponseCode = code },
            request.Questions,
            DomainResourceRecords.Empty);
    }

    private static IDomainClient DelayedClient(DomainMessage response, TimeSpan delay)
    {
        var client = Substitute.For<IDomainClient>();
        client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(ci => DelayedSend(response, delay, ci.Arg<DomainMessage>(), ci.Arg<CancellationToken>()));
        return client;
    }

    private static async ValueTask<DomainMessage> DelayedSend(
        DomainMessage response,
        TimeSpan delay,
        DomainMessage message,
        CancellationToken cancellationToken)
    {
        await Task.Delay(delay, cancellationToken);
        return response with { Id = message.Id };
    }

    private static async ValueTask<DomainMessage> ObserveCancellation(
        DomainMessage message,
        CancellationToken cancellationToken,
        Action<bool> onCancelled)
    {
        try
        {
            await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken);
        }
        catch (OperationCanceledException)
        {
            onCancelled(cancellationToken.IsCancellationRequested);
            throw;
        }

        return DomainMessage.CreateResponse(message, DomainResourceRecords.Empty, DomainResponseCode.NoError);
    }

    private static IDomainClient FixedClient(DomainMessage response)
    {
        var client = Substitute.For<IDomainClient>();
        client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(ci => new ValueTask<DomainMessage>(response with { Id = ci.Arg<DomainMessage>().Id }));
        return client;
    }

    private static IDomainClient ThrowingClient(Exception exception)
    {
        var client = Substitute.For<IDomainClient>();
        client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(_ => ValueTask.FromException<DomainMessage>(exception));
        return client;
    }
}
