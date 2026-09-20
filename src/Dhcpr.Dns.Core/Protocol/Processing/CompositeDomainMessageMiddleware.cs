namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Walks resolver leaves by <see cref="IDomainMessageMiddleware.Priority"/>.
/// Registered as the only <see cref="IDomainMessageMiddleware"/> so Scrutor
/// decorators wrap one pipeline instead of one onion per leaf.
/// </summary>
public sealed class CompositeDomainMessageMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware[] _leaves;

    public CompositeDomainMessageMiddleware(params IDomainMessageMiddleware[] leaves)
    {
        ArgumentNullException.ThrowIfNull(leaves);
        _leaves = leaves.OrderBy(static leaf => leaf.Priority).ToArray();
    }

    public string Name => "Composite";

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        foreach (var leaf in _leaves)
        {
            var response = await leaf.ProcessAsync(context, cancellationToken).ConfigureAwait(false);
            if (context.Cancel)
                return response;
            if (response is not null)
            {
                context.AnsweredBy ??= leaf.Name;
                return response;
            }
        }

        return null;
    }
}
