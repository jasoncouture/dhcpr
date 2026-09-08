using System.Diagnostics;
using System.Diagnostics.Metrics;

using Dhcpr.Dhcp.Core.Pipeline;
using Dhcpr.Dhcp.Core.Protocol;

namespace Dhcpr.Dhcp.Core;

public static class DhcpInstrumentation
{
    public const string MeterName = "Dhcpr.Dhcp";
    public const string ActivitySourceName = "Dhcpr.Dhcp";
    public const string MessagesInstrumentName = "dhcp.messages";
    public const string MessageSpanName = "dhcp.message";

    public static ActivitySource ActivitySource { get; } = new(ActivitySourceName);

    public static Activity? StartMessage(DhcpRequestContext context)
    {
        var activity = Start();
        if (activity is null)
            return null;

        activity.SetTag("dhcp.message.type", MessageTypeName(context.Message));
        activity.SetTag("dhcp.client.mac", context.Message.HardwareAddress.ToString());
        activity.SetTag("network.peer.address", context.Message.ClientAddress.ToString());
        return activity;
    }

    public static void CompleteMessage(Activity? activity, DhcpRequestContext context)
    {
        if (activity is null)
            return;

        if (context.Cancel)
            activity.SetTag("dhcpr.cancelled", true);
        if (context.Response is not null)
            activity.SetTag("dhcp.response.type", MessageTypeName(context.Response));
    }

    public static void RecordMessage(Counter<long> messages, DhcpRequestContext context)
    {
        messages.Add(
            1,
            new KeyValuePair<string, object?>("message_type", MessageTypeName(context.Message)),
            new KeyValuePair<string, object?>("cancelled", context.Cancel),
            new KeyValuePair<string, object?>("replied", context.Response is not null));
    }

    private static Activity? Start()
    {
        if (Activity.Current is { Recorded: true } current)
            return ActivitySource.StartActivity(MessageSpanName, ActivityKind.Server, current.Context);

        if (Activity.Current is not null)
            Activity.Current = null;

        return ActivitySource.StartActivity(MessageSpanName, ActivityKind.Server);
    }

    public static string MessageTypeName(DhcpMessage message)
    {
        var option = message.Options.GetOptionForCode(DhcpOptionCode.DhcpMessageType);
        if (option?.Payload.Length != 1)
            return "unknown";
        return ((DhcpMessageType)option.Payload[0]).ToString("G");
    }
}
