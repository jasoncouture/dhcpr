using System.Diagnostics;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;

public interface IDnsResolver : IRequestResolver
{
}

public class CachedDnsResolver : IDnsResolver
{
    private readonly IDnsOutputFilter _outputFilter;
    private readonly ILogger<CachedDnsResolver> _logger;
    private readonly IRequestResolver _dnsResolverImplementation;

    public CachedDnsResolver(IDnsResolver dnsResolverImplementation, IResolverCache resolverCache,
        IDnsOutputFilter outputFilter, ILogger<CachedDnsResolver> logger)
    {
        _outputFilter = outputFilter;
        _logger = logger;
        _dnsResolverImplementation = resolverCache.WrapWithCache(dnsResolverImplementation);
    }

    public async Task<IResponse> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        var startTimestamp = Stopwatch.GetTimestamp();
        var response = await _dnsResolverImplementation.Resolve(request, cancellationToken);

        response = await _outputFilter.UpdateResponse(this, request, response, cancellationToken);
        var timeTaken = Stopwatch.GetElapsedTime(startTimestamp);
        foreach (var question in request.Questions)
        {
            _logger.LogInformation("DNS resolution for question {question} took {0.0ms}", question,
                timeTaken.TotalMilliseconds);
        }

        return response;
    }
}