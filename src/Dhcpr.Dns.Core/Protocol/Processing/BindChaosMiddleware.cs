using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Class CH is answered locally (never forwarded). BIND identity names
/// (RFC 4892) look like a forgotten RHEL 7 BIND; other CH names are NXDOMAIN.
/// </summary>
public sealed class BindChaosMiddleware : IDomainMessageMiddleware
{
    /// <summary>CVE-2016-2776 and friends. Scanners love this RPM string.</summary>
    public const string VersionText = "9.9.4-P2-RedHat-9.9.4-29.el7_2.3";

    public const string HostnameText = "ns1";

    public const string AuthorsText = "Mark Andrews";

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
        if (question.Class is not DomainRecordClass.CH)
            return await _inner.ProcessAsync(context, cancellationToken);

        // CHAOS is local only — never forward or recurse (a "." route would
        // otherwise send version.bind / random CH names upstream).
        context.AnsweredBy = "bind-chaos";
        context.DoNotCacheResponse = true;
        context.CacheHit = true;

        var response = !IsIdentityName(question.Name)
            ? NxDomain(context.DomainMessage)
            : question.Type is DomainRecordType.TXT or DomainRecordType.ANY
                ? Txt(context.DomainMessage, TextFor(question.Name))
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

    internal static bool IsIdentityName(DomainLabels name)
        => IdentityNames.Contains(name.ToString());

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
}
