using System.Diagnostics;

using Dhcpr.Dhcp.Core;
using Dhcpr.Dhcp.Core.Pipeline;
using Dhcpr.Dhcp.Core.Protocol;

namespace Dhcpr.Dhcp.Core.UnitTests;

public class DhcpInstrumentationTests
{
    [Fact]
    public void MessageTypeNameReadsOption()
    {
        var message = DhcpMessage.Template with
        {
            Options = new DhcpOptionCollection([
                new DhcpOption(DhcpOptionCode.DhcpMessageType, (byte)DhcpMessageType.Discover)
            ])
        };

        Assert.Equal(nameof(DhcpMessageType.Discover), DhcpInstrumentation.MessageTypeName(message));
    }

    [Fact]
    public void MessageTypeNameUnknownWithoutOption()
    {
        Assert.Equal("unknown", DhcpInstrumentation.MessageTypeName(DhcpMessage.Template));
    }

    [Fact]
    public void StartMessageTagsTypeAndMac()
    {
        var started = false;
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == DhcpInstrumentation.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStarted = activity =>
            {
                if (activity.OperationName == DhcpInstrumentation.MessageSpanName)
                    started = true;
            }
        };
        ActivitySource.AddActivityListener(listener);

        var context = new DhcpRequestContext
        {
            NetworkInformation = default!,
            Message = DhcpMessage.Template with
            {
                Options = new DhcpOptionCollection([
                    new DhcpOption(DhcpOptionCode.DhcpMessageType, (byte)DhcpMessageType.Request)
                ])
            }
        };

        using var activity = DhcpInstrumentation.StartMessage(context);

        Assert.True(started);
        Assert.NotNull(activity);
        Assert.Equal(nameof(DhcpMessageType.Request), activity!.GetTagItem("dhcp.message.type"));
    }
}
