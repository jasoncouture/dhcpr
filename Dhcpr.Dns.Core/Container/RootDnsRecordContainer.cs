using Dhcpr.Core.Linq;

namespace Dhcpr.Dns.Core.Container;

public class RootDnsRecordContainer : DnsRecordContainer
{
    public RootDnsRecordContainer() : base("")
    {
        // This is a "root server", since splitting on an initial dot == "", our fragment is ""
    }

    public DnsRecordContainer? Lookup(string domain, int recordType)
    {
        DnsRecordContainer? ret = this;
        DnsRecordContainer? currentContainer = this;

        return GetReversedParts(domain)
            .Aggregate<string, DnsRecordContainer?>
            (
                currentContainer,
                (current, next) => current?.GetChild(next, recordType)
            );
    }

    public DnsRecordContainer? LookupParent(string domain, int recordType)
    {
        var parts = GetReversedParts(domain).ToPooledList();
        parts.RemoveAt(parts.Count - 1);
        parts.Reverse();

        domain = string.Join('.', parts);

        return Lookup(domain, recordType);
    }

    private static IEnumerable<string> GetReversedParts(string domain)
    {
        if (domain.EndsWith('.'))
        {
            domain = domain[..^1];
        }

        if (string.IsNullOrWhiteSpace(domain)) throw new ArgumentException("Invalid domain");
        var domainParts = domain
            .Split('.')
            .Reverse()
            .ToPooledList();
        return domainParts;
    }

    public DnsRecordContainer Create(string domain, int recordType)
    {
        DnsRecordContainer currentContainer = this;

        return GetReversedParts(domain)
            .Aggregate
            (
                currentContainer,
                (current, next) => current.GetOrCreateChild(next, recordType)
            );
    }

    public int CollectGarbage(string domain, int recordType)
    {
        var child = GetChild(domain, recordType);
        if (child is null)
            return 0;
        if (child.IsEmpty())
        {
            RemoveChild(child);
            return 1;
        }

        if (child.GetRecords().Count != 0)
            return 0;
        var explorationQueue =
            new Stack<(DnsRecordContainer container, DnsRecordContainer? parent, bool proceesedChildren)>();
        explorationQueue.Push((child, null, false));
        int removed = 0;
        while (explorationQueue.Count > 0)
        {
            var (next, parent, processedChildren) = explorationQueue.Pop();
            if (next.IsEmpty())
            {
                removed++;
                parent?.RemoveChild(next);
                continue;
            }

            if (processedChildren) continue;
            if (next.GetRecords().Count() != 0) continue;

            // Push ourselves back onto the stack, so we get re-checked after we process our children.
            explorationQueue.Push((next, parent, true));
            foreach (var innerChild in next.GetChildren())
            {
                explorationQueue.Push((innerChild, next, false));
            }
        }

        return removed;
    }
}