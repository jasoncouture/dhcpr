using System.Reflection;

using Dhcpr.Core.Linq;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.Caching.Memory;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.SystemResolver;

public sealed class SystemNameResolver : ISystemNameResolver
{
    private readonly IMemoryCache _cache;

    public SystemNameResolver(IMemoryCache cache)
    {
        _cache = cache;
    }

    public Task<IResponse?> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        return Task.FromResult(ProcessSystemRequest(request));
    }

    private IResponse? ProcessSystemRequest(IRequest request)
    {
        using var nameParts = request.Questions[0].Name.ToString()!
            .ToLower()
            .Split('.')
            .ToPooledList();
        if (nameParts.Count <= 2) return null;
        if (nameParts[^1] != "dhcpr") return null;
        if (request.Questions[0].Type != RecordType.TXT) return NameError(request);

        var module = nameParts[^2];
        nameParts.RemoveAt(nameParts.Count - 1);
        nameParts.RemoveAt(nameParts.Count - 1);
        switch (module)
        {
            case "sys":
                return HandleSystemModule(nameParts, request);
            case "cache":
                return HandleCacheModule(nameParts, request);
            default:
                return NameError(request);
        }
    }

    private IResponse HandleCacheModule(PooledList<string> nameParts, IRequest request)
    {
        if (nameParts.Count != 1)
            return NameError(request);
        if (nameParts[0] != "stats")
            return NameError(request);

        var cacheStatistics = _cache.GetCurrentStatistics();
        if (cacheStatistics is null)
            return NameError(request);

        using var data = ListPool<string>.Default.Get();
        data.Add("cache.hit");
        data.Add(cacheStatistics.TotalHits.ToString());
        data.Add("cache.miss");
        data.Add(cacheStatistics.TotalMisses.ToString());
        data.Add("cache.count");
        data.Add(cacheStatistics.CurrentEntryCount.ToString());
        var estimatedSize = cacheStatistics.CurrentEstimatedSize?.ToString() ?? "Unknown";
        data.Add("cache.size");
        data.Add(estimatedSize);

        return SystemResponse(request, data);
    }

    private static IResponse NameError(IRequest request)
    {
        var response = Response.FromRequest(request);
        response.ResponseCode = ResponseCode.NameError;
        response.AuthorativeServer = true;
        return response;
    }

    private IResponse HandleSystemModule(
        IReadOnlyList<string> nameParts,
        IRequest request
    )
    {
        if (nameParts.Count != 1) return NameError(request);
        switch (nameParts[0])
        {
            case "version":
                var versionString = GetVersionString();
                return SystemResponse(request, $"sys.version", versionString);
            default:
                return NameError(request);
        }
    }

    private static IResponse SystemResponse(IRequest request, params string[] textRecords)
    {
        return SystemResponse(request, textRecords.AsEnumerable());
    }

    private static IResponse SystemResponse(IRequest request, IEnumerable<string> textRecords)
    {
        using var pooledTextRecords = textRecords.ToPooledList();
        if (pooledTextRecords.Count % 2 != 0)
        {
            throw new InvalidOperationException("Data must be divisible by 2");
        }

        var response = Response.FromRequest(request);
        foreach (var textRecord in pooledTextRecords.Chunk(2))
        {
            var textResourceRecord =
                new TextResourceRecord(request.Questions[0].Name, textRecord[0], textRecord[1],
                    ttl: TimeSpan.FromSeconds(30));
            response.AnswerRecords.Add(textResourceRecord);
        }

        response.AuthorativeServer = true;
        response.ResponseCode = ResponseCode.NoError;
        return response;
    }

    private static string? _versionString = null;

    private static string GetVersionString()
    {
        var versionString = _versionString;
        if (versionString is not null) return versionString;
        versionString = Assembly.GetEntryAssembly()?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;
        if (versionString is null) return _versionString = "Unknown";
        return _versionString = versionString;
    }
}