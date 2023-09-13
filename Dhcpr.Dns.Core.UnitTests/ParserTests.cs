using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;

using DNS.Protocol;

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
        var libraryRequestBytes = libraryRequest.ToArray()!;
        var decodedMessage = DomainMessageEncoder.Decode(libraryRequestBytes);
        //Assert.Equal(libraryRequestBytes.Length, decodedMessage.Size);
        Assert.Equal(libraryRequest.Id, decodedMessage.Id);
        Assert.Equal((int)libraryRequest.OperationCode, (int)decodedMessage.Flags.Operation);
        Assert.Equal(libraryRequest.RecursionDesired, decodedMessage.Flags.RecursionDesired);
        Assert.Equal(libraryRequest.Questions.Count, decodedMessage.Questions.Length);
        foreach (var (left, right) in libraryRequest.Questions.Zip(decodedMessage.Questions))
        {
            Assert.Equal(left.Size, right.Size);
            Assert.Equal(left.Name.ToString(), right.Name.ToString());
            Assert.Equal((int)left.Type, (int)right.Type);
            Assert.Equal((int)left.Class, (int)right.Class);
        }

        Span<byte> requestBytes = stackalloc byte[decodedMessage.Size];
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
            DomainResourceRecords.Empty
        );
        Span<byte> data = stackalloc byte[message.Size];
        var bytesWritten = DomainMessageEncoder.Encode(data, message);
        Assert.NotEqual(message.Size, bytesWritten);
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
        
        Span<byte> data = stackalloc byte[message.Size];
        var bytesWritten = DomainMessageEncoder.Encode(data, message);

        var actualMessage = DomainMessageEncoder.Decode(data[..bytesWritten]);
        Assert.Equal(message.Size, actualMessage.Size);
        Assert.Equal(message.Id, actualMessage.Id);
        Assert.Equal(message.Questions.Length, actualMessage.Questions.Length);
    }
}