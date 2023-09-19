using System.Collections.Immutable;
using System.Diagnostics;
using System.Net;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.RecordData;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

namespace Dhcpr.Dns.Core.UnitTests;

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
    public void LabelValidationWorksCorrectly(string label)
    {
        Assert.Matches(DomainNameValidationExtensions.GetLabelRegularExpression(), label);
    }

    [Theory]
    [MemberData(nameof(GetSamplePackets))]
    public void SamplePacketsParse(byte[] data)
    {
        var result = DomainMessageEncoder.Decode(data);
        Assert.NotNull(result);
    }
}

public static class SampleData
{
    public static byte[][] SamplePackets = new[]
    {
        new byte[]
        {
            183, 6, 129, 0, 0, 1, 0, 0, 0, 13, 0, 15, 3, 99, 111, 109, 0, 0, 2, 0, 1, 192, 12, 0, 2, 0, 1, 0, 2,
            163, 0, 0, 20, 1, 102, 12, 103, 116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101,
            116, 0, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 97, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0,
            0, 4, 1, 108, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 100, 192, 35, 192, 12, 0, 2, 0,
            1, 0, 2, 163, 0, 0, 4, 1, 105, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 98, 192, 35,
            192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 103, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4,
            1, 99, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 101, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2,
            163, 0, 0, 4, 1, 106, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 104, 192, 35, 192, 12, 0,
            2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 107, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 109, 192,
            35, 192, 241, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 55, 83, 30, 192, 81, 0, 1, 0, 1, 0, 2, 163, 0, 0,
            4, 192, 41, 162, 30, 192, 225, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 52, 178, 30, 192, 193, 0, 1, 0,
            1, 0, 2, 163, 0, 0, 4, 192, 48, 79, 30, 192, 113, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 43, 172, 30,
            192, 209, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 54, 112, 30, 192, 145, 0, 1, 0, 1, 0, 2, 163, 0, 0,
            4, 192, 42, 93, 30, 192, 33, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 35, 51, 30, 192, 177, 0, 1, 0, 1,
            0, 2, 163, 0, 0, 4, 192, 12, 94, 30, 192, 97, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 31, 80, 30, 192,
            161, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 26, 92, 30, 192, 129, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192,
            33, 14, 30, 192, 65, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 5, 6, 30, 192, 241, 0, 28, 0, 1, 0, 2,
            163, 0, 0, 16, 32, 1, 5, 1, 177, 249, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 192, 81, 0, 28, 0, 1, 0, 2,
            163, 0, 0, 16, 32, 1, 5, 0, 217, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48,
        }
    };
}