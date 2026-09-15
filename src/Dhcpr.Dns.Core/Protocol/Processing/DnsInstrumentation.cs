using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public static class DnsInstrumentation
{
    public const string ActivitySourceName = "Dhcpr.Dns";
    public const string QuerySpanName = "dns.query";
    public const string InternalSpanName = "dns.internal";
    public const string UpstreamSpanName = "dns.upstream";

    public static ActivitySource ActivitySource { get; } = new(ActivitySourceName);

    public static ActivityContext CaptureContext()
        => Activity.Current?.Context ?? default;

    public static Activity? StartQuery(DnsPacketReceivedMessage message)
    {
        var context = message.Context;
        var name = context.IsInternal ? InternalSpanName : QuerySpanName;
        var kind = context.IsInternal ? ActivityKind.Internal : ActivityKind.Server;
        var activity = context.ParentTraceContext != default
            ? ActivitySource.StartActivity(name, kind, context.ParentTraceContext)
            : ActivitySource.StartActivity(name, kind);
        if (activity is null)
            return null;

        activity.SetTag("network.transport", Transport(message));
        if (context.ClientEndPoint is { } client)
        {
            activity.SetTag("network.peer.address", client.Address.ToString());
            activity.SetTag("network.peer.port", client.Port);
        }

        if (context.ServerEndPoint is { } server)
        {
            activity.SetTag("server.address", server.Address.ToString());
            activity.SetTag("server.port", server.Port);
        }

        activity.SetTag("dhcpr.internal", context.IsInternal);
        activity.SetTag("dhcpr.hop_depth", context.InternalHopDepth);
        SetQuestionTags(activity, context.DomainMessage);
        return activity;
    }

    public static void CompleteQuery(Activity? activity, DomainMessageContext context, DomainMessage? response)
    {
        if (activity is null)
            return;

        activity.SetTag("dhcpr.cache_hit", context.CacheHit);
        if (context.AnsweredBy is { } answeredBy)
            activity.SetTag("dhcpr.answered_by", answeredBy);

        if (response is null)
        {
            activity.SetStatus(ActivityStatusCode.Error, "no response");
            return;
        }

        activity.SetTag("dns.response.code", response.Flags.ResponseCode.ToString("G"));
        if (response.Flags.ResponseCode is DomainResponseCode.ServerFailure)
            activity.SetStatus(ActivityStatusCode.Error, context.ServFailReason ?? "SERVFAIL");
    }

    public static Activity? StartUpstream(System.Net.IPEndPoint target, string transport, DomainMessage message)
    {
        var activity = ActivitySource.StartActivity(UpstreamSpanName, ActivityKind.Client);
        if (activity is null)
            return null;

        activity.SetTag("server.address", target.Address.ToString());
        activity.SetTag("server.port", target.Port);
        activity.SetTag("network.transport", transport);
        SetQuestionTags(activity, message);
        return activity;
    }

    public static void CompleteUpstream(Activity? activity, DomainMessage response)
    {
        if (activity is null)
            return;

        activity.SetTag("dns.response.code", response.Flags.ResponseCode.ToString("G"));
        if (response.Flags.ResponseCode is DomainResponseCode.ServerFailure)
            activity.SetStatus(ActivityStatusCode.Error, "SERVFAIL");
    }

    public static void RecordDuration(
        Histogram<double> duration,
        DomainMessageContext context,
        DomainMessage? response,
        TimeSpan elapsed)
    {
        if (context.IsInternal || context.BypassCache)
            return;

        if (response is null && context.AnsweredBy is not "UdpRateLimit")
            return;

        var question = context.DomainMessage.Questions.IsDefaultOrEmpty
            ? null
            : context.DomainMessage.Questions[0];
        var rcode = response is null
            ? DnsMetrics.DropRcode
            : response.Flags.ResponseCode.ToString("G");
        var error = response is null ||
                    response.Flags.ResponseCode is not DomainResponseCode.NoError;
        duration.Record(
            elapsed.TotalSeconds,
            new KeyValuePair<string, object?>("cache_hit", context.CacheHit),
            new KeyValuePair<string, object?>("error", error),
            new KeyValuePair<string, object?>("rcode", rcode),
            new KeyValuePair<string, object?>("query_type", question?.Type.ToString("G") ?? "none"),
            new KeyValuePair<string, object?>("answered_by", context.AnsweredBy ?? "resolver"),
            new KeyValuePair<string, object?>("source", context.Source.ToMetricLabel()));
    }

    /// <summary>
    /// One outbound nameserver query. Directed hops are included — they are
    /// the RTTs <c>dns.query.duration</c> cannot show.
    /// </summary>
    public static void RecordUpstream(
        Histogram<double> duration,
        Counter<long> queries,
        string transport,
        DomainMessage request,
        DomainMessage? response,
        bool cancelled,
        bool error,
        TimeSpan elapsed)
    {
        var question = request.Questions.IsDefaultOrEmpty ? null : request.Questions[0];
        var rcode = response is null
            ? DnsMetrics.NoneRcode
            : response.Flags.ResponseCode.ToString("G");
        var queryType = question?.Type.ToString("G") ?? DnsMetrics.NoneRcode;
        duration.Record(
            elapsed.TotalSeconds,
            new KeyValuePair<string, object?>("network.transport", transport),
            new KeyValuePair<string, object?>("error", error),
            new KeyValuePair<string, object?>("cancelled", cancelled),
            new KeyValuePair<string, object?>("rcode", rcode),
            new KeyValuePair<string, object?>("query_type", queryType));
        queries.Add(
            1,
            new KeyValuePair<string, object?>("network.transport", transport),
            new KeyValuePair<string, object?>("error", error),
            new KeyValuePair<string, object?>("cancelled", cancelled),
            new KeyValuePair<string, object?>("rcode", rcode),
            new KeyValuePair<string, object?>("query_type", queryType));
    }

    private static void SetQuestionTags(Activity activity, DomainMessage message)
    {
        if (message.Questions.IsDefaultOrEmpty)
            return;

        var question = message.Questions[0];
        activity.SetTag("dns.question.name", question.Name.ToString());
        activity.SetTag("dns.question.type", question.Type.ToString("G"));
        activity.SetTag("dns.question.class", question.Class.ToString("G"));
        activity.SetTag("dns.question.count", message.Questions.Length);
    }

    private static string Transport(DnsPacketReceivedMessage message)
    {
        if (message.Context.IsInternal)
            return "internal";

        return message.Context.Source switch
        {
            DnsQuerySource.Udp => "udp",
            DnsQuerySource.Tcp => "tcp",
            DnsQuerySource.Dot => "dot",
            DnsQuerySource.Doh => "doh",
            _ => message switch
            {
                UdpDnsPacketReceivedMessage => "udp",
                TcpDnsPacketReceivedMessage => "tcp",
                HttpDnsPacketReceivedMessage => "doh",
                _ => "unknown"
            }
        };
    }
}
