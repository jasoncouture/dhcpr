using System.Xml.Linq;

using Dhcpr.Server.Orleans.DataProtection;

using Microsoft.Extensions.Logging.Abstractions;

using Orleans;

using NSubstitute;

namespace Dhcpr.Server.UnitTests;

[Collection(nameof(DataProtectionKeySnapshot))]
public class OrleansDataProtectionKeyRepositoryTests
{
    public OrleansDataProtectionKeyRepositoryTests()
    {
        DataProtectionKeySnapshot.Clear();
    }

    [Fact]
    public void GetAllElementsReadsLocalSnapshot()
    {
        DataProtectionKeySnapshot.Replace(
        [
            """<key id="a" version="1"/>""",
            """<key id="b" version="1"/>"""
        ]);
        var grain = Substitute.For<IDataProtectionKeyGrain>();
        var grains = Substitute.For<IGrainFactory>();
        grains.GetGrain<IDataProtectionKeyGrain>(DataProtectionKeyGrain.Key).Returns(grain);

        var repository = new OrleansDataProtectionKeyRepository(grains);
        var elements = repository.GetAllElements();

        Assert.Equal(2, elements.Count);
        Assert.Equal("a", elements.ElementAt(0).Attribute("id")?.Value);
        Assert.Equal("b", elements.ElementAt(1).Attribute("id")?.Value);
        grain.DidNotReceive().GetAllAsync();
    }

    [Fact]
    public void StoreElementWritesXmlToGrainAndSnapshot()
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
        Assert.Contains(DataProtectionKeySnapshot.Get(), xml => xml.Contains("id=\"c\"") || xml.Contains("id='c'"));
    }
}

[Collection(nameof(DataProtectionKeySnapshot))]
public class DataProtectionKeyGrainTests
{
    public DataProtectionKeyGrainTests()
    {
        DataProtectionKeySnapshot.Clear();
    }

    [Fact]
    public async Task OnActivateBootstrapsFromLocalSnapshot()
    {
        DataProtectionKeySnapshot.Replace(["""<key id="a"/>"""]);
        var grain = new DataProtectionKeyGrain(NullLogger<DataProtectionKeyGrain>.Instance);

        await grain.OnActivateAsync(CancellationToken.None);
        var keys = await grain.GetAllAsync();

        Assert.Equal(["""<key id="a"/>"""], keys);
    }

    [Fact]
    public async Task StoreKeepsKeyOnGrain()
    {
        var grain = new DataProtectionKeyGrain(NullLogger<DataProtectionKeyGrain>.Instance);
        await grain.OnActivateAsync(CancellationToken.None);

        await grain.StoreAsync("""<key id="b"/>""", "b");

        Assert.Equal(["""<key id="b"/>"""], await grain.GetAllAsync());
    }
}

[CollectionDefinition(nameof(DataProtectionKeySnapshot))]
public sealed class DataProtectionKeySnapshotCollection : ICollectionFixture<DataProtectionKeySnapshotCollection>;
