namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class QueryWorkBudget
{
    public const int DefaultLimit = 64;

    private int _remaining;

    public QueryWorkBudget(int limit = DefaultLimit)
    {
        _remaining = limit;
    }

    public bool TryConsume() => Interlocked.Decrement(ref _remaining) >= 0;
}
