using DNS.Client.RequestResolver;
using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers;

public interface IDnsOutputFilter
{
    Task<IResponse> UpdateResponse(IRequestResolver resolver, IRequest request, IResponse? response,
        CancellationToken cancellationToken);
}