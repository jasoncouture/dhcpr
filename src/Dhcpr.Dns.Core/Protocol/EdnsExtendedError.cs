using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Text;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol;

/// <summary>
/// RFC 8914 Extended DNS Error. Option code 15. Info-code 0 (Other) carries
/// the EXTRA-TEXT when no registered purpose matches.
/// </summary>
public static class EdnsExtendedError
{
    public const ushort OptionCode = 15;
    public const ushort Other = 0;
    public const ushort DnssecBogus = 6;
    public const ushort SignatureExpired = 7;
    public const ushort SignatureNotYetValid = 8;
    public const ushort DnskeyMissing = 9;
    public const string LoopDetectedText = "Loop Detected";

    public static DomainResourceRecord Create(ushort infoCode)
        => Create(infoCode, string.Empty);

    public static DomainResourceRecord Create(ushort infoCode, string extraText)
    {
        var text = Encoding.UTF8.GetBytes(extraText);
        var data = new byte[2 + text.Length];
        BinaryPrimitives.WriteUInt16BigEndian(data, infoCode);
        text.CopyTo(data.AsSpan(2));

        return new DomainResourceRecord(
            DomainLabels.Empty,
            DomainRecordType.OPT,
            (DomainRecordClass)1232,
            TimeSpan.Zero,
            new OptionData(ImmutableArray.Create(new EdnsOption(OptionCode, ImmutableArray.Create(data)))));
    }
}
