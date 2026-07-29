using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.UnitTests;

public class DomainLabelsEqualityTests
{
    [Fact]
    public void EqualNamesFromSeparateInstances_AreEqual()
    {
        var a = new DomainLabels("Example.COM");
        var b = new DomainLabels("example.com");
        Assert.Equal(a, b);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    [Fact]
    public void GroupByNameType_CollapsesSameOwner()
    {
        var records = Enumerable.Range(0, 5).Select(_ => new DomainResourceRecord(
            new DomainLabels("net"),
            DomainRecordType.NS,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(60),
            new Protocol.RecordData.NameData(new DomainLabels($"ns{_}.example"))))
            .ToList();

        var groups = records.GroupBy(r => r.Name).ToList();
        Assert.Single(groups);
        Assert.Equal(5, groups[0].Count());
    }
}
