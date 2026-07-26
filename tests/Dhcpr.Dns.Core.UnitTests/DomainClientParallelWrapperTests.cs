using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class DomainClientParallelWrapperTests
{
    [Fact]
    public async Task AllUnacceptableResponsesReturnServerFailure()
    {
        var failure = CreateResponse(DomainResponseCode.ServerFailure, truncated: false);
        using var wrapper = new DomainClientParallelWrapper(new IDomainClient[]
        {
            new DelayedClient(failure, TimeSpan.Zero),
            new DelayedClient(failure, TimeSpan.Zero)
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
            new DelayedClient(failure, TimeSpan.FromMilliseconds(10)),
            new DelayedClient(success, TimeSpan.FromMilliseconds(50))
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
            new DelayedClient(nameError, TimeSpan.FromMilliseconds(10)),
            new DelayedClient(success, TimeSpan.FromMilliseconds(50))
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
            new DelayedClient(nameError, TimeSpan.FromMilliseconds(10)),
            new ThrowingClient(new IOException("timed out"))
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
            new DelayedClient(nameError, TimeSpan.Zero),
            new DelayedClient(nameError, TimeSpan.Zero)
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
            new DelayedClient(truncated, TimeSpan.FromMilliseconds(10)),
            new DelayedClient(complete, TimeSpan.FromMilliseconds(40))
        });

        var result = await wrapper.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None);
        Assert.False(result.Flags.Truncated);
    }

    [Fact]
    public async Task TimeoutWrapperCancelsViaLinkedToken()
    {
        var inner = new TokenObservingClient(TimeSpan.FromSeconds(5));
        using var wrapper = new DomainClientTimeoutWrapper(inner, TimeSpan.FromMilliseconds(50));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
            await wrapper.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None));

        Assert.True(inner.SawCancellation);
    }

    [Fact]
    public async Task TruncationFallbackRetriesOverTcp()
    {
        var udp = new FixedClient(CreateResponse(DomainResponseCode.NoError, truncated: true));
        var tcp = new FixedClient(CreateResponse(DomainResponseCode.NoError, truncated: false));
        using var wrapper = new DomainClientTruncationFallbackWrapper(udp, tcp);

        var result = await wrapper.SendAsync(DomainMessage.CreateRequest("example.com"), CancellationToken.None);

        Assert.False(result.Flags.Truncated);
        Assert.Equal(1, udp.CallCount);
        Assert.Equal(1, tcp.CallCount);
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

    private sealed class DelayedClient : IDomainClient
    {
        private readonly DomainMessage _response;
        private readonly TimeSpan _delay;

        public DelayedClient(DomainMessage response, TimeSpan delay)
        {
            _response = response;
            _delay = delay;
        }

        public async ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
        {
            await Task.Delay(_delay, cancellationToken);
            return _response with { Id = message.Id };
        }
    }

    private sealed class FixedClient : IDomainClient
    {
        private readonly DomainMessage _response;
        public int CallCount { get; private set; }

        public FixedClient(DomainMessage response) => _response = response;

        public ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
        {
            CallCount++;
            return ValueTask.FromResult(_response with { Id = message.Id });
        }
    }

    private sealed class ThrowingClient : IDomainClient
    {
        private readonly Exception _exception;

        public ThrowingClient(Exception exception) => _exception = exception;

        public ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
            => ValueTask.FromException<DomainMessage>(_exception);
    }

    private sealed class TokenObservingClient : IDomainClient
    {
        private readonly TimeSpan _delay;
        public bool SawCancellation { get; private set; }

        public TokenObservingClient(TimeSpan delay) => _delay = delay;

        public async ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
        {
            try
            {
                await Task.Delay(_delay, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                SawCancellation = cancellationToken.IsCancellationRequested;
                throw;
            }

            return DomainMessage.CreateResponse(message, DomainResourceRecords.Empty, DomainResponseCode.NoError);
        }
    }
}
