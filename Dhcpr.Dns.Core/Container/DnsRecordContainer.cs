using Dhcpr.Core.Linq;

using DNS.Protocol.ResourceRecords;

namespace Dhcpr.Dns.Core.Container;

public class DnsRecordContainer
{
    public bool IsEmpty()
    {
        lock (_records)
            if (_records.Count != 0)
                return false;
        lock (Containers)
            if (Containers.Count != 0)
                return false;
        return true;
    }

    public string Fragment { get; }

    public void ClearRecords()
    {
        lock (_records) _records.Clear();
    }

    internal IEnumerable<DnsRecordContainer> GetChildren()
    {
        lock (Containers)
            return Containers.Values.ToPooledList();
    }

    public void ClearSubdomains()
    {
        lock (Containers) Containers.Clear();
    }

    private Dictionary<(string fragment, int recordType), DnsRecordContainer> Containers { get; } = new();

    private PooledList<IResourceRecord> _records = ListPool<IResourceRecord>.Default.Get();

    public PooledList<IResourceRecord> GetRecords()
    {
        lock (_records)
            return _records.ToPooledList();
    }

    protected DnsRecordContainer(string fragment)
    {
        Fragment = fragment;
    }

    protected internal DnsRecordContainer? GetChild(string fragment, int recordType)
    {
        lock (Containers)
        {
            return Containers.TryGetValue((fragment, recordType), out var item) ? item : null;
        }
    }

    protected internal DnsRecordContainer GetOrCreateChild(string fragment, int recordType)
    {
        DnsRecordContainer? ret;

        lock (Containers)
        {
            // ReSharper disable once InvertIf
            if (!Containers.TryGetValue((fragment, recordType), out ret))
            {
                ret = new DnsRecordContainer(fragment);
                Containers.Add((fragment, recordType), ret);
            }
        }

        return ret;
    }

    public void RemoveChild(DnsRecordContainer container)
    {
        PooledList<KeyValuePair<(string Fragment, int recordType), DnsRecordContainer>>
            containers;

        lock (Containers)
            containers = Containers.ToPooledList();


        foreach (var record in containers.Where(record => record.Value == container))
        {
            lock (Containers)
                Containers.Remove(record.Key);
        }
    }
}