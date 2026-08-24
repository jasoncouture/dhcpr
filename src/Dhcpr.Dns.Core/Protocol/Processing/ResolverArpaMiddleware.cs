using System.Net;
using System.Net.Sockets;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// RFC 9462 Discovery of Designated Resolvers: serve <c>resolver.arpa</c> locally
/// so SVCB at <c>_dns.resolver.arpa</c> never leaks to the public DNS.
/// </summary>
public sealed class ResolverArpaMiddleware : IDomainMessageMiddleware
{
    public const string Zone = "resolver.arpa";
    public const string DiscoveryName = "_dns.resolver.arpa";
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(300);

    private readonly IDomainMessageMiddleware _inner;
    private readonly IOptionsMonitor<DnsConfiguration> _options;

    public ResolverArpaMiddleware(
        IDomainMessageMiddleware inner,
        IOptionsMonitor<DnsConfiguration> options)
    {
        _inner = inner;
        _options = options;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (context.DomainMessage.Questions.IsDefaultOrEmpty)
            return await _inner.ProcessAsync(context, cancellationToken);

        var question = context.DomainMessage.Questions[0];
        if (!IsUnderResolverArpa(question.Name))
            return await _inner.ProcessAsync(context, cancellationToken);

        context.AnsweredBy = "resolver.arpa";
        context.DoNotCacheResponse = true;

        var response = question.Type is DomainRecordType.SVCB && IsDiscoveryName(question.Name)
            ? CreateDiscoveryResponse(context.DomainMessage)
            : Nodata(context.DomainMessage);

        return response with
        {
            Flags = response.Flags with
            {
                Authoritative = true,
                RecursionAvailable = true
            }
        };
    }

    internal static bool IsUnderResolverArpa(DomainLabels name)
    {
        var qname = name.ToString();
        return qname.Equals(Zone, StringComparison.OrdinalIgnoreCase) ||
               qname.EndsWith($".{Zone}", StringComparison.OrdinalIgnoreCase);
    }

    internal static bool IsDiscoveryName(DomainLabels name)
        => name.ToString().Equals(DiscoveryName, StringComparison.OrdinalIgnoreCase);

    private DomainMessage CreateDiscoveryResponse(DomainMessage request)
    {
        var designated = _options.CurrentValue.DesignatedResolvers;
        if (designated is not { Length: > 0 })
            return Nodata(request);

        var owner = request.Questions[0].Name;
        var answers = new List<DomainResourceRecord>(designated.Length);
        var additional = new List<DomainResourceRecord>();
        foreach (var resolver in designated)
        {
            var target = new DomainLabels(resolver.Target);
            answers.Add(new DomainResourceRecord(
                owner,
                DomainRecordType.SVCB,
                DomainRecordClass.IN,
                Ttl,
                ToSvcbData(resolver, target)));

            foreach (var hint in resolver.Ipv4Hint)
            {
                additional.Add(new DomainResourceRecord(
                    target,
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    Ttl,
                    new IPAddressData(IPAddress.Parse(hint))));
            }

            foreach (var hint in resolver.Ipv6Hint)
            {
                additional.Add(new DomainResourceRecord(
                    target,
                    DomainRecordType.AAAA,
                    DomainRecordClass.IN,
                    Ttl,
                    new IPAddressData(IPAddress.Parse(hint))));
            }
        }

        return DomainMessage.CreateResponse(
            request,
            answers,
            additional: additional,
            responseCode: DomainResponseCode.NoError);
    }

    private static SvcbData ToSvcbData(DesignatedResolverConfiguration designated, DomainLabels target)
    {
        var parameters = new List<SvcbParameter>();
        if (designated.Alpn is { Length: > 0 })
            parameters.Add(SvcbParameter.Alpn(designated.Alpn));
        if (designated.Port is { } port)
            parameters.Add(SvcbParameter.Port((ushort)port));
        if (designated.Ipv4Hint is { Length: > 0 })
        {
            parameters.Add(SvcbParameter.Ipv4Hint(
                designated.Ipv4Hint.Select(static h => IPAddress.Parse(h)).ToArray()));
        }

        if (designated.Ipv6Hint is { Length: > 0 })
        {
            parameters.Add(SvcbParameter.Ipv6Hint(
                designated.Ipv6Hint.Select(static h => IPAddress.Parse(h)).ToArray()));
        }

        if (!string.IsNullOrEmpty(designated.DohPath))
            parameters.Add(SvcbParameter.DohPath(designated.DohPath));

        return new SvcbData((ushort)designated.Priority, target, [.. parameters]);
    }

    private static DomainMessage Nodata(DomainMessage request)
        => DomainMessage.CreateResponse(
            request,
            DomainResourceRecords.Empty,
            DomainResponseCode.NoError);
}
