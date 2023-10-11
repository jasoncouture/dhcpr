using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Files;

namespace Dhcpr.Dns.Core.UnitTests;

[SuppressMessage("ReSharper", "ClassCanBeSealed.Global")]
public class LabelLookupCollectionTests
{
    [Fact]
    public void CanAddAndGetItem()
    {
        var expected = new object();
        var labels = new[] { "www", "google", "com" };
        using var collection = LabelLookupCollectionPool<object>.Get();
        Assert.False(collection.TryGetValue(labels, out _));
        Assert.True(collection.TryAdd(labels, expected));
        Assert.True(collection.TryGetValue(labels, out var actual));
        Assert.NotNull(actual);
        Assert.Equal(expected, actual);
        Assert.False(collection.TryAdd(labels, expected));
        Assert.True(collection.TryRemove(labels));
        Assert.False(collection.TryRemove(labels));
    }
}