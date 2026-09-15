using System.Diagnostics;
using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class TracingDomainClient : IDomainClient
{
    private readonly IDomainClient _inner;
    private readonly IPEndPoint _target;
    private readonly string _transport;
    private readonly DnsUpstreamMetrics _metrics;

    public TracingDomainClient(
        IDomainClient inner,
        IPEndPoint target,
        string transport,
        DnsUpstreamMetrics metrics)
    {
        _inner = inner;
        _target = target;
        _transport = transport;
        _metrics = metrics;
    }

    public async ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
    {
        using var activity = DnsInstrumentation.StartUpstream(_target, _transport, message);
        var started = Stopwatch.GetTimestamp();
        DomainMessage? response = null;
        var cancelled = false;
        var error = false;
        try
        {
            response = await _inner.SendAsync(message, cancellationToken);
            DnsInstrumentation.CompleteUpstream(activity, response);
            return response;
        }
        catch (OperationCanceledException)
        {
            // Race cancel: the token we were given is cancelled.
            // Timeout: inner wrapper cancels its own CTS; our token is still open.
            cancelled = cancellationToken.IsCancellationRequested;
            error = !cancelled;
            activity?.SetTag("dhcpr.cancelled", true);
            throw;
        }
        catch (Exception ex)
        {
            error = true;
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
        finally
        {
            _metrics.Record(
                _transport,
                message,
                response,
                cancelled,
                error,
                Stopwatch.GetElapsedTime(started));
        }
    }

    public void Dispose() => _inner.Dispose();
}
