using System.Net;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Only class IN is forwarded or recursed. CH is answered locally (BIND
/// identity bait, <c>ip.info</c> client address, or NXDOMAIN). Every other
/// class is NOTIMP.
/// </summary>
public sealed class BindChaosMiddleware : IDomainMessageMiddleware
{
    /// <summary>CVE-2016-2776 and friends. Scanners love this RPM string.</summary>
    public const string VersionText = "9.9.4-P2-RedHat-9.9.4-29.el7_2.3";

    public const string HostnameText = "ns1";

    public const string AuthorsText = "Mark Andrews";

    public const string IpInfoName = "ip.info";

    public const string UnknownClientText = "unknown";

    internal static readonly TimeSpan Ttl = TimeSpan.Zero;

    private static readonly HashSet<string> IdentityNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "version.bind",
        "hostname.bind",
        "authors.bind",
        "id.server",
        "version.server"
    };

    private readonly IDomainMessageMiddleware _inner;

    public BindChaosMiddleware(IDomainMessageMiddleware inner)
    {
        _inner = inner;
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
        if (question.Class is DomainRecordClass.IN)
            return await _inner.ProcessAsync(context, cancellationToken);

        // Non-IN never leaves the process (a "." route would otherwise
        // send CHAOS / Hesiod / QCLASS ANY upstream).
        context.DoNotCacheResponse = true;
        context.CacheHit = true;

        if (question.Class is not DomainRecordClass.CH)
        {
            context.AnsweredBy = "query-class";
            return Local(context.DomainMessage, DomainResponseCode.NotImplemented, authoritative: false);
        }

        context.AnsweredBy = "bind-chaos";
        var response = IsIpInfo(question.Name)
            ? question.Type is DomainRecordType.TXT or DomainRecordType.ANY
                ? Txt(context.DomainMessage, ClientAddressText(context.ClientEndPoint))
                : Nodata(context.DomainMessage)
            : !IsIdentityName(question.Name)
                ? NxDomain(context.DomainMessage)
                : question.Type is DomainRecordType.TXT or DomainRecordType.ANY
                    ? Txt(context.DomainMessage, TextFor(question.Name))
                    : Nodata(context.DomainMessage);

        return Local(response, response.Flags.ResponseCode, authoritative: true);
    }

    internal static bool IsIdentityName(DomainLabels name)
        => IdentityNames.Contains(name.ToString());

    internal static bool IsIpInfo(DomainLabels name)
        => name.ToString().Equals(IpInfoName, StringComparison.OrdinalIgnoreCase);

    internal static string ClientAddressText(IPEndPoint? client)
    {
        var address = client?.Address;
        if (address is null || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
            return UnknownClientText;

        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        return address.ToString();
    }

    internal static string TextFor(DomainLabels name)
        => name.ToString().ToLowerInvariant() switch
        {
            "version.bind" or "version.server" => VersionText,
            "hostname.bind" or "id.server" => HostnameText,
            "authors.bind" => AuthorsText,
            _ => VersionText
        };

    private static DomainMessage Txt(DomainMessage request, string text)
        => DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    request.Questions[0].Name,
                    DomainRecordType.TXT,
                    DomainRecordClass.CH,
                    Ttl,
                    new TextData(text))
            ],
            responseCode: DomainResponseCode.NoError);

    private static DomainMessage Nodata(DomainMessage request)
        => DomainMessage.CreateResponse(
            request,
            DomainResourceRecords.Empty,
            DomainResponseCode.NoError);

    private static DomainMessage NxDomain(DomainMessage request)
        => DomainMessage.CreateResponse(
            request,
            DomainResourceRecords.Empty,
            DomainResponseCode.NameError);

    private static DomainMessage Local(
        DomainMessage message,
        DomainResponseCode responseCode,
        bool authoritative)
    {
        var response = message.Flags.Response
            ? message
            : DomainMessage.CreateResponse(message, DomainResourceRecords.Empty, responseCode);

        return response with
        {
            Flags = response.Flags with
            {
                Authoritative = authoritative,
                RecursionAvailable = true,
                ResponseCode = responseCode
            }
        };
    }
}
