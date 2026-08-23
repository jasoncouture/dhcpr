using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.UnitTests;

public class EstimatedSizeTests
{
    [Fact]
    public void WithAddedAnswersFitsInRecomputedEstimatedSize()
    {
        var request = DomainMessage.CreateRequest("ichnaea-web.netflix.com");
        var cnameOnly = DomainMessage.CreateResponse(
            request,
            new[]
            {
                Cname(
                    "ichnaea-web.netflix.com",
                    "ichnaea-web.dradis.netflix.com")
            },
            responseCode: DomainResponseCode.NoError);

        // Cache replica encode reads size on the hop response before CNAME
        // chase grows the assembly. A cached _size would stay too small.
        var hopSize = cnameOnly.EstimatedSize;

        var assembled = cnameOnly with
        {
            Records = cnameOnly.Records with
            {
                Answers = cnameOnly.Records.Answers.AddRange(
                    new[]
                    {
                        Cname(
                            "ichnaea-web.dradis.netflix.com",
                            "ichnaea-web.us-east-2.internal.dradis.netflix.com"),
                        Cname(
                            "ichnaea-web.us-east-2.internal.dradis.netflix.com",
                            "apiproxy-log-nlb.elb.us-east-2.amazonaws.com"),
                        A("apiproxy-log-nlb.elb.us-east-2.amazonaws.com", IPAddress.Parse("3.21.189.253")),
                        A("apiproxy-log-nlb.elb.us-east-2.amazonaws.com", IPAddress.Parse("3.147.179.10")),
                        A("apiproxy-log-nlb.elb.us-east-2.amazonaws.com", IPAddress.Parse("18.119.152.119"))
                    })
            }
        };

        Assert.True(assembled.EstimatedSize > hopSize);

        var buffer = new byte[assembled.EstimatedSize];
        var written = DomainMessageEncoder.Encode(buffer, assembled);
        Assert.True(written <= assembled.EstimatedSize);
        Assert.True(written > hopSize);
    }

    [Fact]
    public void EmptyRecordsWithAnswersReportsNonZeroSize()
    {
        Assert.Equal(0, DomainResourceRecords.Empty.EstimatedSize);

        var grown = DomainResourceRecords.Empty with
        {
            Answers = ImmutableArray.Create(
                A("example.com", IPAddress.Loopback))
        };

        Assert.True(grown.EstimatedSize > 0);
    }

    private static DomainResourceRecord Cname(string owner, string target)
        => new(
            new DomainLabels(owner),
            DomainRecordType.CNAME,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(60),
            new NameData(new DomainLabels(target)));

    private static DomainResourceRecord A(string owner, IPAddress address)
        => new(
            new DomainLabels(owner),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(60),
            new IPAddressData(address));
}
