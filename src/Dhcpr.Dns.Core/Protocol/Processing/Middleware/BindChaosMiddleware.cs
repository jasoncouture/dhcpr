using System.Net;
using System.Reflection;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Processing.Middleware;

/// <summary>
/// CH is answered locally (<c>id.server</c> and <c>version.server</c>
/// return the application name and version, <c>ip.info</c> the client
/// address, or NXDOMAIN). IN and every other class pass through;
/// <see cref="UnsupportedQueryTypeMiddleware"/> NOTIMPs non-IN/CH.
/// </summary>
public sealed class BindChaosMiddleware : IDomainMessageMiddleware
{
    public const string ApplicationName = "dhcpr";

    public static readonly string IdentityText = Describe(typeof(BindChaosMiddleware).Assembly);

    public const string IpInfoName = "ip.info";

    public const string UnknownClientText = "unknown";

    internal static readonly TimeSpan Ttl = TimeSpan.Zero;

    /// <summary>Identity TXT lifetime so the response cache will store it.</summary>
    public static readonly TimeSpan IdentityTtl = TimeSpan.FromSeconds(60);

    private static readonly HashSet<string> IdentityNames = new(StringComparer.OrdinalIgnoreCase)
    {
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

    public async ValueTask<DomainMessage> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (context.DomainMessage.Questions.IsDefaultOrEmpty)
            return await _inner.ProcessAsync(context, cancellationToken);

        var question = context.DomainMessage.Questions[0];
        if (question.Class is not DomainRecordClass.CH)
            return await _inner.ProcessAsync(context, cancellationToken);

        // CHAOS never leaves the process (a "." route would otherwise
        // send id.server upstream). Identity answers are cached;
        // ip.info is not — that TXT is the client address.
        context.AnsweredBy = "chaos";
        if (IsIpInfo(question.Name))
        {
            context.DoNotCacheResponse = true;
            var ipResponse = question.Type is DomainRecordType.TXT or DomainRecordType.ANY
                ? Txt(context.DomainMessage, ClientAddressText(context.ClientEndPoint), Ttl)
                : Nodata(context.DomainMessage);
            return Local(ipResponse, ipResponse.Flags.ResponseCode, authoritative: true);
        }

        var response = !IsIdentityName(question.Name)
            ? NxDomain(context.DomainMessage)
            : question.Type is DomainRecordType.TXT or DomainRecordType.ANY
                ? Txt(context.DomainMessage, IdentityText, IdentityTtl)
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

    internal static string Describe(Assembly assembly)
    {
        var informational = assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational))
            return $"{ApplicationName} {informational}";

        var version = assembly.GetName().Version?.ToString();
        if (!string.IsNullOrWhiteSpace(version))
            return $"{ApplicationName} {version}";

        return ApplicationName;
    }

    private static DomainMessage Txt(DomainMessage request, string text, TimeSpan ttl)
        => DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    request.Questions[0].Name,
                    DomainRecordType.TXT,
                    DomainRecordClass.CH,
                    ttl,
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
