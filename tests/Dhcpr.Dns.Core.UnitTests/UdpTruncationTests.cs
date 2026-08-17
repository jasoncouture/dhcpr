using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.UnitTests;

public class UdpTruncationTests
{
    [Fact]
    public void TruncateAndEncodeMessageSetsTruncatedWhenRecordsDropped()
    {
        var answers = Enumerable.Range(1, 40)
            .Select(i => new DomainResourceRecord(
                new DomainLabels("example.com"),
                DomainRecordType.A,
                DomainRecordClass.IN,
                TimeSpan.FromSeconds(60),
                new IPAddressData(IPAddress.Parse($"10.0.0.{i}"))))
            .ToImmutableArray();

        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(request, answers, responseCode: DomainResponseCode.NoError);

        var buffer = new byte[4096];
        var written = DomainMessageContextMessageProcessor.TruncateAndEncodeMessage(response, 512, buffer);
        var decoded = DomainMessageEncoder.Decode(buffer.AsSpan(0, written));

        Assert.True(written <= 512);
        Assert.True(decoded.Flags.Truncated);
        Assert.True(decoded.Records.Answers.Length < 40);
    }
}
