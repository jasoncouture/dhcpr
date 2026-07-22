using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.RecordData;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

namespace Dhcpr.Dns.Core.UnitTests;

[SuppressMessage("ReSharper", "ClassCanBeSealed.Global")]
public class ParserTests
{
    [Fact]
    public void BitEncoderWorks()
    {
        const ushort testValue = 2;

        Assert.False(DomainMessageEncoder.ReadBit(testValue, 0));
        Assert.True(DomainMessageEncoder.ReadBit(testValue, 1));
        Assert.False(DomainMessageEncoder.ReadBit(testValue, 2));
    }

    [Fact]
    public void ParserCanParseMessagesFromOtherLibraries()
    {
        var libraryRequest = new Request { Id = 1234, RecursionDesired = true };
        libraryRequest.Questions.Add(new Question(new Domain("www.google.com")));
        libraryRequest.AdditionalRecords.Add(new NameServerResourceRecord(new Domain("fake.net"),
            new Domain("fake2.org")));
        libraryRequest.AdditionalRecords.Add(new IPAddressResourceRecord(new Domain("fake3.edu"), IPAddress.Broadcast));
        var libraryRequestBytes = libraryRequest.ToArray()!;
        var decodedMessage = DomainMessageEncoder.Decode(libraryRequestBytes);
        //Assert.Equal(libraryRequestBytes.Length, decodedMessage.Size);
        Assert.Equal(libraryRequest.Id, decodedMessage.Id);
        Assert.Equal((int)libraryRequest.OperationCode, (int)decodedMessage.Flags.Operation);
        Assert.Equal(libraryRequest.RecursionDesired, decodedMessage.Flags.RecursionDesired);
        Assert.Equal(libraryRequest.Questions.Count, decodedMessage.Questions.Length);
        foreach (var (left, right) in libraryRequest.Questions.Zip(decodedMessage.Questions))
        {
            Assert.Equal(left.Size, right.EstimatedSize);
            Assert.Equal(left.Name.ToString(), right.Name.ToString());
            Assert.Equal((int)left.Type, (int)right.Type);
            Assert.Equal((int)left.Class, (int)right.Class);
        }

        Assert.IsType<NameData>(decodedMessage.Records.Additional[0].Data);
        Assert.IsType<IPAddressData>(decodedMessage.Records.Additional[1].Data);

        Span<byte> requestBytes = stackalloc byte[decodedMessage.EstimatedSize];
        DomainMessageEncoder.Encode(requestBytes, decodedMessage);

        Assert.Equal(libraryRequestBytes, requestBytes.ToArray());
    }

    [Fact]
    public void LabelsAreCompressedWhenEncoding()
    {
        var message = new DomainMessage(1234,
            new DomainMessageFlags(false, DomainOperationCode.Query, false, false, true, false, false, false,
                DomainResponseCode.NoError),
            new[]
            {
                new DomainQuestion(new DomainLabels("www.google.com"), DomainRecordType.A, DomainRecordClass.Any),
                new DomainQuestion(new DomainLabels("www.google.com"), DomainRecordType.AAAA,
                    DomainRecordClass.Any),
                new DomainQuestion(new DomainLabels("www.google.com"), DomainRecordType.CNAME,
                    DomainRecordClass.Any),
            }.ToImmutableArray(),
            new DomainResourceRecords(
                ImmutableArray<DomainResourceRecord>.Empty,
                ImmutableArray<DomainResourceRecord>.Empty,
                new[]
                {
                    new DomainResourceRecord(new DomainLabels("www.google.com"), DomainRecordType.NS,
                        DomainRecordClass.IN, TimeSpan.FromSeconds(5),
                        new NameData(new DomainLabels("www.google.com")))
                }.ToImmutableArray()
            )
        );
        Span<byte> data = stackalloc byte[message.EstimatedSize];
        var bytesWritten = DomainMessageEncoder.Encode(data, message);
        Assert.NotEqual(message.EstimatedSize, bytesWritten);
    }

    [Fact]
    public void ParserCanParseItsOwnOutput()
    {
        var message = new DomainMessage(1234,
            new DomainMessageFlags(false, DomainOperationCode.Query, false, false, true, false, false, false,
                DomainResponseCode.NoError),
            new[]
            {
                new DomainQuestion(new DomainLabels("www.google.com"), DomainRecordType.A, DomainRecordClass.Any),
                new DomainQuestion(new DomainLabels("www.google.com"), DomainRecordType.AAAA,
                    DomainRecordClass.Any),
                new DomainQuestion(new DomainLabels("www.google.com"), DomainRecordType.CNAME,
                    DomainRecordClass.Any),
            }.ToImmutableArray(),
            DomainResourceRecords.Empty
        );

        Span<byte> data = stackalloc byte[message.EstimatedSize];
        var bytesWritten = DomainMessageEncoder.Encode(data, message);

        var actualMessage = DomainMessageEncoder.Decode(data[..bytesWritten]);
        Assert.Equal(message.EstimatedSize, actualMessage.EstimatedSize);
        Assert.Equal(message.Id, actualMessage.Id);
        Assert.Equal(message.Questions.Length, actualMessage.Questions.Length);
    }

    [Fact]
    public void EdnsOptRecordEncodesAndDecodesCorrectly()
    {
        var ednsProtocolService = new EdnsProtocolService();
        var optData = new OptData(new[] { new EdnsOption(10, ImmutableArray.Create<byte>(1, 2, 3, 4)) }.ToImmutableArray());
        var optRecord = ednsProtocolService.CreateOptRecord(4096, dnssecOk: true, extendedRCode: 1, version: 0, optData: optData);

        var message = new DomainMessage(1234,
            new DomainMessageFlags(false, DomainOperationCode.Query, false, false, true, false, false, false,
                DomainResponseCode.NoError),
            new[] { new DomainQuestion(new DomainLabels("www.google.com"), DomainRecordType.A, DomainRecordClass.Any) }.ToImmutableArray(),
            new DomainResourceRecords(
                ImmutableArray<DomainResourceRecord>.Empty,
                ImmutableArray<DomainResourceRecord>.Empty,
                new[] { optRecord }.ToImmutableArray()
            )
        );

        Span<byte> data = stackalloc byte[message.EstimatedSize];
        var bytesWritten = DomainMessageEncoder.Encode(data, message);

        var decodedMessage = DomainMessageEncoder.Decode(data[..bytesWritten]);
        var decodedRecord = decodedMessage.Records.Additional[0];

        Assert.Equal(DomainRecordType.OPT, decodedRecord.Type);
        Assert.True(ednsProtocolService.IsDnssecOk(decodedRecord));
        Assert.Equal(4096, ednsProtocolService.GetUdpPayloadSize(decodedRecord));
        Assert.Equal(1, ednsProtocolService.GetExtendedRCode(decodedRecord));
        Assert.Equal(0, ednsProtocolService.GetEdnsVersion(decodedRecord));
        
        var decodedOptData = Assert.IsType<OptData>(decodedRecord.Data);
        var decodedOption = Assert.Single(decodedOptData.Options);
        Assert.Equal(10, decodedOption.Code);
        Assert.Equal(new byte[] { 1, 2, 3, 4 }, decodedOption.Data.ToArray());
    }

    [Fact]
    public void DnsKeyRecordEncodesAndDecodesCorrectly()
    {
        var keyData = new DnsKeyData(256, 3, 8, ImmutableArray.Create<byte>(1, 2, 3, 4, 5));
        var record = new DomainResourceRecord(new DomainLabels("example.com"), DomainRecordType.DNSKEY, DomainRecordClass.IN, TimeSpan.FromSeconds(3600), keyData);
        var message = DomainMessage.CreateResponse(DomainMessage.CreateRequest("example.com"), new[] { record });

        Span<byte> data = stackalloc byte[message.EstimatedSize];
        var bytesWritten = DomainMessageEncoder.Encode(data, message);

        var decodedMessage = DomainMessageEncoder.Decode(data[..bytesWritten]);
        var decodedRecord = decodedMessage.Records.Answers[0];
        
        var decodedKeyData = Assert.IsType<DnsKeyData>(decodedRecord.Data);
        Assert.Equal(256, decodedKeyData.Flags);
        Assert.Equal(3, decodedKeyData.Protocol);
        Assert.Equal(8, decodedKeyData.Algorithm);
        Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, decodedKeyData.PublicKey.ToArray());
    }

    [Fact]
    public void DsRecordEncodesAndDecodesCorrectly()
    {
        var dsData = new DsData(12345, 8, 2, ImmutableArray.Create<byte>(9, 8, 7, 6));
        var record = new DomainResourceRecord(new DomainLabels("example.com"), DomainRecordType.DS, DomainRecordClass.IN, TimeSpan.FromSeconds(3600), dsData);
        var message = DomainMessage.CreateResponse(DomainMessage.CreateRequest("example.com"), new[] { record });

        Span<byte> data = stackalloc byte[message.EstimatedSize];
        var bytesWritten = DomainMessageEncoder.Encode(data, message);

        var decodedMessage = DomainMessageEncoder.Decode(data[..bytesWritten]);
        var decodedRecord = decodedMessage.Records.Answers[0];
        
        var decodedDsData = Assert.IsType<DsData>(decodedRecord.Data);
        Assert.Equal(12345, decodedDsData.KeyTag);
        Assert.Equal(8, decodedDsData.Algorithm);
        Assert.Equal(2, decodedDsData.DigestType);
        Assert.Equal(new byte[] { 9, 8, 7, 6 }, decodedDsData.Digest.ToArray());
    }

    [Fact]
    public void RrSigRecordEncodesAndDecodesCorrectly()
    {
        var rrsigData = new RrSigData(DomainRecordType.A, 8, 2, 3600, 1690000000, 1680000000, 12345, new DomainLabels("example.com"), ImmutableArray.Create<byte>(1, 3, 5, 7));
        var record = new DomainResourceRecord(new DomainLabels("example.com"), DomainRecordType.RRSIG, DomainRecordClass.IN, TimeSpan.FromSeconds(3600), rrsigData);
        var message = DomainMessage.CreateResponse(DomainMessage.CreateRequest("example.com"), new[] { record });

        Span<byte> data = stackalloc byte[message.EstimatedSize];
        var bytesWritten = DomainMessageEncoder.Encode(data, message);

        var decodedMessage = DomainMessageEncoder.Decode(data[..bytesWritten]);
        var decodedRecord = decodedMessage.Records.Answers[0];
        
        var decodedRrSigData = Assert.IsType<RrSigData>(decodedRecord.Data);
        Assert.Equal(DomainRecordType.A, decodedRrSigData.TypeCovered);
        Assert.Equal(8, decodedRrSigData.Algorithm);
        Assert.Equal(2, decodedRrSigData.Labels);
        Assert.Equal(3600u, decodedRrSigData.OriginalTtl);
        Assert.Equal(1690000000u, decodedRrSigData.SignatureExpiration);
        Assert.Equal(1680000000u, decodedRrSigData.SignatureInception);
        Assert.Equal(12345, decodedRrSigData.KeyTag);
        Assert.Equal("example.com", decodedRrSigData.SignersName.ToString());
        Assert.Equal(new byte[] { 1, 3, 5, 7 }, decodedRrSigData.Signature.ToArray());
    }

    public static IEnumerable<object[]> GetSamplePackets()
    {
        foreach (var sample in SampleData.SamplePackets)
        {
            yield return new object[] { sample };
        }
    }

    [Theory]
    [InlineData("m")]
    [InlineData("a0")]
    [InlineData("gtld-servers")]
    [InlineData("70046ujm1swdqc9mj1tj7l71in215vaa")]
    [InlineData("3com")]
    public void LabelValidationWorksCorrectly(string label)
    {
        Assert.Matches(DomainNameValidationExtensions.GetLabelRegularExpression(), label);
    }

    [Theory]
    [InlineData("-bad")]
    [InlineData("bad-")]
    [InlineData("")]
    public void LabelValidationRejectsInvalidLabels(string label)
    {
        Assert.DoesNotMatch(DomainNameValidationExtensions.GetLabelRegularExpression(), label);
    }

    [Theory]
    [MemberData(nameof(GetSamplePackets))]
    public void SamplePacketsParse(byte[] data)
    {
        var result = DomainMessageEncoder.Decode(data);
        Assert.NotNull(result);
    }
}