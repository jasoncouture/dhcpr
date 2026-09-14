using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// BIND-style CHAOS identity names (RFC 4892). Same joke TXT for every
/// well-known name — no version, hostname, or instance id.
/// </summary>
public sealed class BindChaosMiddleware : IDomainMessageMiddleware
{
    public const string AnswerText = "sorry, we're not running bind, nice try.";
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
        if (question.Class is not DomainRecordClass.CH || !IsIdentityName(question.Name))
            return await _inner.ProcessAsync(context, cancellationToken);

        context.AnsweredBy = "bind-chaos";
        context.DoNotCacheResponse = true;
        context.CacheHit = true;

        var response = question.Type is DomainRecordType.TXT or DomainRecordType.ANY
            ? Txt(context.DomainMessage)
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

    private static DomainMessage Txt(DomainMessage request)
        => DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    request.Questions[0].Name,
                    DomainRecordType.TXT,
                    DomainRecordClass.CH,
                    Ttl,
                    new TextData(AnswerText))
            ],
            responseCode: DomainResponseCode.NoError);

    private static DomainMessage Nodata(DomainMessage request)
        => DomainMessage.CreateResponse(
            request,
            DomainResourceRecords.Empty,
            DomainResponseCode.NoError);
}
