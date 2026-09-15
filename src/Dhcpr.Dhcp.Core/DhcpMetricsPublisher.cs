using System.Diagnostics;

using Dhcpr.Core.Metrics;
using Dhcpr.Dhcp.Core.Pipeline;

namespace Dhcpr.Dhcp.Core;

public sealed class DhcpMetricsPublisher : IDhcpMetrics
{
    private readonly IPublishedCounter _messages;

    public DhcpMetricsPublisher(IMetricPublisher metrics)
    {
        _messages = metrics.CreateCounter(
            DhcpInstrumentation.MeterName,
            DhcpInstrumentation.MessagesInstrumentName,
            unit: "{message}",
            description: "DHCP messages processed");
    }

    public void RecordMessage(DhcpRequestContext context)
    {
        var tags = new TagList
        {
            { "message_type", DhcpInstrumentation.MessageTypeName(context.Message) },
            { "cancelled", context.Cancel },
            { "replied", context.Response is not null }
        };
        _messages.Add(1, in tags);
    }
}
