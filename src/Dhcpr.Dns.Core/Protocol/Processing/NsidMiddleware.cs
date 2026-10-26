using System.Collections.Immutable;
using System.Text;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// RFC 5001. When the query carries NSID, the reply includes this host's name.
/// Outside the cache, so the stored message does not keep the name.
/// </summary>
public sealed class NsidMiddleware : IDomainMessageMiddleware
{
    private const ushort OptionCode = 3;
    private readonly IDomainMessageMiddleware _inner;

    public NsidMiddleware(IDomainMessageMiddleware inner)
    {
        _inner = inner;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var result = await _inner.ProcessAsync(context, cancellationToken);
        if (context.IsInternal || !Requested(context.DomainMessage))
            return result;

        var machine = Environment.MachineName.ToLower();
        Span<byte> name = stackalloc byte[Encoding.UTF8.GetMaxByteCount(machine.Length)];
        var written = Encoding.UTF8.GetBytes(machine, name);
        return Attach(result, name[..written]);
    }

    private static bool Requested(DomainMessage message)
    {
        foreach (var record in message.Records.Additional)
        {
            if (record.Type is not DomainRecordType.OPT || record.Data is not OptionData data)
                continue;

            foreach (var option in data.Options)
            {
                if (option.Code == OptionCode)
                    return true;
            }
        }

        return false;
    }

    private static DomainMessage Attach(DomainMessage response, ReadOnlySpan<byte> payload)
    {
        var additional = response.Records.Additional;
        var optIndex = -1;
        for (var i = 0; i < additional.Length; i++)
        {
            if (additional[i].Type is DomainRecordType.OPT)
            {
                optIndex = i;
                break;
            }
        }

        var nsid = new EdnsOption(OptionCode, ImmutableArray.Create(payload));
        if (optIndex < 0)
        {
            var opt = new DomainResourceRecord(
                DomainLabels.Empty,
                DomainRecordType.OPT,
                (DomainRecordClass)1232,
                TimeSpan.Zero,
                new OptionData(ImmutableArray.Create(nsid)));
            return response with
            {
                Records = response.Records with { Additional = additional.Add(opt) }
            };
        }

        var existingOpt = additional[optIndex];
        var existing = existingOpt.Data as OptionData ?? new OptionData(ImmutableArray<EdnsOption>.Empty);
        var kept = existing.Options.Where(static o => o.Code != OptionCode).ToImmutableArray();
        kept = kept.Add(nsid);

        var additionalBuilder = additional.ToBuilder();
        additionalBuilder[optIndex] = existingOpt with { Data = new OptionData(kept) };
        return response with
        {
            Records = response.Records with { Additional = additionalBuilder.ToImmutable() }
        };
    }
}
