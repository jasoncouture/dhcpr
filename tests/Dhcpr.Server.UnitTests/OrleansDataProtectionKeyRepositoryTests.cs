using System.Xml.Linq;

using Dhcpr.Server.Orleans.DataProtection;

using Orleans;

using NSubstitute;

namespace Dhcpr.Server.UnitTests;

public class OrleansDataProtectionKeyRepositoryTests
{
    [Fact]
    public void GetAllElementsParsesStoredXml()
    {
        var grain = Substitute.For<IDataProtectionKeyGrain>();
        grain.GetAllAsync().Returns(Task.FromResult<IReadOnlyList<string>>(
        [
            """<key id="a" version="1"/>""",
            """<key id="b" version="1"/>"""
        ]));
        var grains = Substitute.For<IGrainFactory>();
        grains.GetGrain<IDataProtectionKeyGrain>(DataProtectionKeyGrain.Key).Returns(grain);

        var repository = new OrleansDataProtectionKeyRepository(grains);
        var elements = repository.GetAllElements();

        Assert.Equal(2, elements.Count);
        Assert.Equal("a", elements.ElementAt(0).Attribute("id")?.Value);
        Assert.Equal("b", elements.ElementAt(1).Attribute("id")?.Value);
    }

    [Fact]
    public void StoreElementWritesXmlToGrain()
    {
        var grain = Substitute.For<IDataProtectionKeyGrain>();
        grain.StoreAsync(Arg.Any<string>(), Arg.Any<string?>()).Returns(Task.CompletedTask);
        var grains = Substitute.For<IGrainFactory>();
        grains.GetGrain<IDataProtectionKeyGrain>(DataProtectionKeyGrain.Key).Returns(grain);

        var repository = new OrleansDataProtectionKeyRepository(grains);
        repository.StoreElement(new XElement("key", new XAttribute("id", "c")), "key-c");

        grain.Received(1).StoreAsync(
            Arg.Is<string>(xml => xml.Contains("id=\"c\"") || xml.Contains("id='c'")),
            "key-c");
    }
}
