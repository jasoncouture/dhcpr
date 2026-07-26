namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class QueryWorkBudget
{
    // Cold CNAME chains (e.g. ingest → findingest → multi-cut leaf) share one budget across
    // recursion + glue A/AAAA fan-out. 64 was enough to SERVFAIL the first query and succeed warm.
    public const int DefaultLimit = 256;

    private int _remaining;

    public QueryWorkBudget(int limit = DefaultLimit)
    {
        _remaining = limit;
    }

    public bool TryConsume() => Interlocked.Decrement(ref _remaining) >= 0;
}
