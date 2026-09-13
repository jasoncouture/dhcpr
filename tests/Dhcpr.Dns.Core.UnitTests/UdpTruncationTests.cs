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

    [Fact]
    public void UdpAmplificationGuardLeavesSmallAnswersIntact()
    {
        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    new DomainLabels("example.com"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new IPAddressData(IPAddress.Parse("93.184.216.34")))
            ],
            responseCode: DomainResponseCode.NoError);

        var guarded = DomainMessageContextMessageProcessor.ApplyUdpAmplificationGuard(response);

        Assert.Same(response, guarded);
        Assert.False(guarded.Flags.Truncated);
        Assert.Single(guarded.Records.Answers);
    }

    [Fact]
    public void UdpAmplificationGuardEmptiesOversizedTxt()
    {
        var request = DomainMessage.CreateRequest("cisco.com", DomainRecordType.TXT);
        var answers = Enumerable.Range(0, 20)
            .Select(i => new DomainResourceRecord(
                new DomainLabels("cisco.com"),
                DomainRecordType.TXT,
                DomainRecordClass.IN,
                TimeSpan.FromSeconds(300),
                new TextData(new string('x', 200) + i)))
            .ToImmutableArray();
        var response = DomainMessage.CreateResponse(request, answers, responseCode: DomainResponseCode.NoError);

        Assert.True(response.EstimatedSize > DomainMessageContextMessageProcessor.UdpResponseSizeLimit);

        var guarded = DomainMessageContextMessageProcessor.ApplyUdpAmplificationGuard(response);

        Assert.True(guarded.Flags.Truncated);
        Assert.Empty(guarded.Records.Answers);
        Assert.Empty(guarded.Records.Authorities);
        Assert.Empty(guarded.Records.Additional);
        Assert.True(guarded.EstimatedSize <= DomainMessageContextMessageProcessor.UdpResponseSizeLimit);

        var buffer = new byte[4096];
        var written = DomainMessageContextMessageProcessor.TruncateAndEncodeMessage(
            guarded,
            DomainMessageContextMessageProcessor.UdpResponseSizeLimit,
            buffer);
        Assert.True(written <= DomainMessageContextMessageProcessor.UdpResponseSizeLimit);
        Assert.True(DomainMessageEncoder.Decode(buffer.AsSpan(0, written)).Flags.Truncated);
    }
}
