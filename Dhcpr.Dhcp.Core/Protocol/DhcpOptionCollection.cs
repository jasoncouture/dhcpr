using System.Collections;
using System.Collections.Immutable;

using Dhcpr.Core.Linq;

namespace Dhcpr.Dhcp.Core.Protocol;

public sealed record DhcpOptionCollection(ImmutableArray<DhcpOption> Options) : IEnumerable<DhcpOption>
{
    private DhcpOptionCollection() : this(ImmutableArray<DhcpOption>.Empty) { }

    public DhcpOptionCollection(IEnumerable<DhcpOption> options) : this(options.ToImmutableArray()) { }

    public IEnumerable<DhcpOption> WithOnlyOptionCodes(IEnumerable<DhcpOptionCode> codes, bool appendEndCode = false,
        bool rapidCommit = false)
    {
        using var codesList = codes.Distinct().ToPooledList();
        if (rapidCommit)
            yield return DhcpOption.RapidCommit;
        foreach (var option in this)
        {
            if (!codesList.Contains(option.Code))
                continue;
            yield return option;
        }


        if (appendEndCode)
            yield return DhcpOption.End;
    }

    public void WriteAndAdvance(ref Span<byte> buffer, IEnumerable<DhcpOptionCode>? optionCodes = null,
        bool includeEndMarker = false, bool rapidCommit = false)
    {
        IEnumerable<DhcpOption> options = this;
        if (optionCodes != null)
        {
            options = this.WithOnlyOptionCodes(optionCodes, includeEndMarker, rapidCommit);
        }

        foreach (var option in options)
        {
            option.WriteAndAdvance(ref buffer);
        }
    }

    public static DhcpOptionCollection Empty { get; } = new();
    private readonly int? _length;
    private Dictionary<DhcpOptionCode, IEnumerable<DhcpOption>>? _optionsDictionary;

    private static Dictionary<DhcpOptionCode, IEnumerable<DhcpOption>> CreateOptionsDictionary(
        IEnumerable<DhcpOption> options)
        => options.GroupBy(i => i.Code).ToDictionary(i => i.Key, i => i.AsEnumerable());

    public Dictionary<DhcpOptionCode, IEnumerable<DhcpOption>> OptionsLookup =>
        _optionsDictionary ??= CreateOptionsDictionary(Options);

    public int Length => Options.Select(i => i.Length).DefaultIfEmpty(0).Sum(i => i);

    public IEnumerator<DhcpOption> GetEnumerator()
    {
        return Options.AsEnumerable().GetEnumerator();
    }

    public IEnumerable<DhcpOption> GetOptionsForCode(DhcpOptionCode code)
    {
        OptionsLookup.TryGetValue(code, out var options);
        return options ?? Enumerable.Empty<DhcpOption>();
    }

    public DhcpOption? GetOptionForCode(DhcpOptionCode code)
    {
        return GetOptionsForCode(code).SingleOrDefault();
    }

    public override string ToString()
    {
        return string.Concat($"{{ {Environment.NewLine}",
            string.Join($",{Environment.NewLine}", Options.Select(i => $"\t{i.ToString()}")),
            $"{Environment.NewLine}}}");
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return GetEnumerator();
    }
}