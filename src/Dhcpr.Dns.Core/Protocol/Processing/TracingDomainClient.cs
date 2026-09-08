using System.Diagnostics;
using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class TracingDomainClient : IDomainClient
{
    private readonly IDomainClient _inner;
    private readonly IPEndPoint _target;
    private readonly string _transport;

    public TracingDomainClient(IDomainClient inner, IPEndPoint target, string transport)
    {
        _inner = inner;
        _target = target;
        _transport = transport;
    }

    public async ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
    {
        using var activity = DnsInstrumentation.StartUpstream(_target, _transport, message);
        try
        {
            var response = await _inner.SendAsync(message, cancellationToken);
            DnsInstrumentation.CompleteUpstream(activity, response);
            return response;
        }
        catch (Exception ex)
        {
            activity?.SetStatus(ActivityStatusCode.Error, ex.Message);
            throw;
        }
    }

    public void Dispose() => _inner.Dispose();
}
