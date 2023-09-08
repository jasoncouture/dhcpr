using Dhcpr.Core.Linq;

using DNS.Client.RequestResolver;
using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers;

public abstract class MultiResolver : IMultiResolver
{
    public abstract Task<IResponse?> Resolve(IRequest request, CancellationToken cancellationToken = new CancellationToken());
    private readonly HashSet<IRequestResolver> _innerResolvers = new();

    public void ReplaceResolvers(params IRequestResolver[] resolvers)
    {
        lock (_innerResolvers)
        {
            _innerResolvers.Clear();
            foreach (var resolver in resolvers)
            {
                _innerResolvers.Add(resolver);
            }
        }
    }
    public void AddResolvers(params IRequestResolver[] resolvers)
    {
        foreach(var resolver in resolvers)
            AddResolver(resolver);
    }

    public void AddResolver(IRequestResolver resolver)
    {
        lock(_innerResolvers)
            _innerResolvers.Add(resolver);
    }

    public void RemoveResolver(IRequestResolver resolver)
    {
        lock (_innerResolvers)
            _innerResolvers.Remove(resolver);
    }

    protected PooledList<IRequestResolver> Resolvers
    {
        get
        {
            lock (_innerResolvers)
                return _innerResolvers.ToPooledList();
        }
    }
}

