using System.Xml.Linq;

using Dhcpr.Core;
using Dhcpr.Server.Orleans.DataProtection;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

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

        var repository = new OrleansDataProtectionKeyRepository(CreateFiles());
        var elements = repository.GetAllElements();

        Assert.Equal(2, elements.Count);
        Assert.Contains(elements, static e => e.Attribute("id")?.Value == "a");
        Assert.Contains(elements, static e => e.Attribute("id")?.Value == "b");
    }

    [Fact]
    public void StoreElementWritesXmlToDiskAndSnapshot()
    {
        var directory = Directory.CreateTempSubdirectory();
        try
        {
            var files = CreateFiles(directory.FullName);
            var repository = new OrleansDataProtectionKeyRepository(files);
            repository.StoreElement(new XElement("key", new XAttribute("id", "c")), "key-c");

            Assert.Contains(DataProtectionKeySnapshot.Copy(), xml => xml.Contains("id=\"c\"") || xml.Contains("id='c'"));

            DataProtectionKeySnapshot.Clear();
            _ = CreateFiles(directory.FullName);
            Assert.Contains(DataProtectionKeySnapshot.Copy(), xml => xml.Contains("id=\"c\"") || xml.Contains("id='c'"));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static DataProtectionKeyFiles CreateFiles(string? path = null)
    {
        path ??= Directory.CreateTempSubdirectory().FullName;
        return new DataProtectionKeyFiles(Options.Create(new ApplicationConfiguration { DataPath = path }));
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
