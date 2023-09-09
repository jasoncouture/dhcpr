using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Protocol;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsCacheTests
{
    [Fact]
    public void DifferentReferenceObjectsWithSameDataAreConsideredEqual()
    {
        var query1 = new QueryCacheKey("abc", RecordType.A, RecordClass.IN);
        var query2 = new QueryCacheKey("abc", RecordType.A, RecordClass.IN);

        Assert.Equal(query1, query2);
    }

    [Fact]
    public void MemoryCacheRespectsValueEqualityOfKeyRecords()
    {
        var memoryCache = new MemoryCache(new MemoryCacheOptions(), new NullLoggerFactory());
        var query1 = new QueryCacheKey("abc", RecordType.A, RecordClass.IN);
        var query2 = new QueryCacheKey("abc", RecordType.A, RecordClass.IN);
        const string expectedResult = "abc123";

        memoryCache.Set(query1, expectedResult);
        var actualResult = memoryCache.Get<string>(query2);
        Assert.Equal(expectedResult, actualResult);
    }
}