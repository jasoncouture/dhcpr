using Dhcpr.Dns.Core.Protocol;

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
        var libraryRequest = new Request();
        libraryRequest.Id = 1234;
        libraryRequest.RecursionDesired = true;
        libraryRequest.Questions.Add(new Question(new Domain("www.google.com")));
        var libraryRequestBytes = libraryRequest.ToArray()!;
        var decodedMessage = DomainMessageEncoder.Decode(libraryRequestBytes);
        Assert.Equal(libraryRequestBytes.Length, decodedMessage.Size);
        Assert.Equal(libraryRequest.Id, decodedMessage.Flags.Id);
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
    
    
}