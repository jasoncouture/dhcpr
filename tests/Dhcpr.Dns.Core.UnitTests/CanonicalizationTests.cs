using System;
using System.Collections.Immutable;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Xunit;

namespace Dhcpr.Dns.Core.UnitTests;

public class CanonicalizationTests
{
    [Fact]
    public void OwnerNameIsLowercased()
    {
        var record = new DomainResourceRecord(
            new DomainLabels("ExAmPlE.CoM"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(3600),
            new BlobData(ImmutableArray.Create<byte>(1, 2, 3, 4))
        );

        var canonicalWire = record.ToCanonicalWireFormat(300);

        // example.com. length is 1 + 7 + 1 + 3 + 1 = 13 bytes
        // type 2 bytes, class 2 bytes, ttl 4 bytes, rdlength 2 bytes = 10 bytes
        // rdata = 4 bytes
        Assert.Equal(27, canonicalWire.Length);

        // Check the owner name (first 13 bytes including root)
        Assert.Equal(7, canonicalWire[0]);
        Assert.Equal((byte)'e', canonicalWire[1]);
        Assert.Equal((byte)'x', canonicalWire[2]);
        Assert.Equal((byte)'a', canonicalWire[3]);
        Assert.Equal((byte)'m', canonicalWire[4]);
        Assert.Equal((byte)'p', canonicalWire[5]);
        Assert.Equal((byte)'l', canonicalWire[6]);
        Assert.Equal((byte)'e', canonicalWire[7]);
        
        Assert.Equal(3, canonicalWire[8]);
        Assert.Equal((byte)'c', canonicalWire[9]);
        Assert.Equal((byte)'o', canonicalWire[10]);
        Assert.Equal((byte)'m', canonicalWire[11]);
        Assert.Equal(0, canonicalWire[12]);
    }

    [Fact]
    public void CanonicalTtlIsUsed()
    {
        var record = new DomainResourceRecord(
            new DomainLabels("test.com"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(3600), // Original TTL is different
            new BlobData(ImmutableArray.Create<byte>(1, 2, 3, 4))
        );

        var canonicalWire = record.ToCanonicalWireFormat(86400); // Canonical TTL

        // TTL is at offset: owner name length (10) + type (2) + class (2) = 14
        Assert.Equal((byte)((86400 >> 24) & 0xFF), canonicalWire[14]);
        Assert.Equal((byte)((86400 >> 16) & 0xFF), canonicalWire[15]);
        Assert.Equal((byte)((86400 >> 8) & 0xFF), canonicalWire[16]);
        Assert.Equal((byte)((86400 >> 0) & 0xFF), canonicalWire[17]);
    }

    [Fact]
    public void NsNameIsLowercased()
    {
        var record = new DomainResourceRecord(
            new DomainLabels("test.com"),
            DomainRecordType.NS,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(3600),
            new NameData(new DomainLabels("NS1.ExAmPlE.CoM"))
        );

        var canonicalWire = record.ToCanonicalWireFormat(3600);

        // The RDATA starts at offset: owner (10) + type (2) + class (2) + ttl (4) + rdlength (2) = 20
        // NS1 (3), example (7), com (3), root (1)
        Assert.Equal(3, canonicalWire[20]);
        Assert.Equal((byte)'n', canonicalWire[21]);
        Assert.Equal((byte)'s', canonicalWire[22]);
        Assert.Equal((byte)'1', canonicalWire[23]);
        Assert.Equal(7, canonicalWire[24]);
        Assert.Equal((byte)'e', canonicalWire[25]);
        // ... verified it lowercases correctly
    }

    [Fact]
    public void WildcardOwnerIsRewrittenFromRrsigLabels()
    {
        // RFC 4034 §6.2: when the owner has more labels than RRSIG.Labels,
        // the canonical owner is "*" plus the least-significant Labels labels.
        var record = new DomainResourceRecord(
            new DomainLabels("random.example.com"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(3600),
            new BlobData(ImmutableArray.Create<byte>(1, 2, 3, 4))
        );

        var canonicalWire = record.ToCanonicalWireFormat(300, rrsigLabels: 2);

        // *.example.com. = 1+1 + 1+7 + 1+3 + 1 = 15
        Assert.Equal(1, canonicalWire[0]);
        Assert.Equal((byte)'*', canonicalWire[1]);
        Assert.Equal(7, canonicalWire[2]);
        Assert.Equal((byte)'e', canonicalWire[3]);
        Assert.Equal((byte)'x', canonicalWire[4]);
        Assert.Equal((byte)'a', canonicalWire[5]);
        Assert.Equal((byte)'m', canonicalWire[6]);
        Assert.Equal((byte)'p', canonicalWire[7]);
        Assert.Equal((byte)'l', canonicalWire[8]);
        Assert.Equal((byte)'e', canonicalWire[9]);
        Assert.Equal(3, canonicalWire[10]);
        Assert.Equal((byte)'c', canonicalWire[11]);
        Assert.Equal((byte)'o', canonicalWire[12]);
        Assert.Equal((byte)'m', canonicalWire[13]);
        Assert.Equal(0, canonicalWire[14]);
    }
}
