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
    public const ushort RrsigsMissing = 10;
    public const ushort NsecMissing = 12;
    public const ushort CachedError = 13;
    public const ushort Blocked = 15;
    public const ushort Prohibited = 18;
    public const ushort NotSupported = 21;
    public const ushort NoReachableAuthority = 22;
    public const ushort NetworkError = 23;
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

    public static DomainMessage ServFail(DomainMessage request, ushort infoCode)
        => DomainMessage.CreateResponse(
            request,
            additional: [Create(infoCode)],
            responseCode: DomainResponseCode.ServerFailure);

    public static DomainMessage Attach(DomainMessage message, ushort infoCode)
    {
        if (Contains(message, infoCode))
            return message;

        var ede = new EdnsOption(OptionCode, ImmutableArray.Create(Encode(infoCode)));
        var additional = message.Records.Additional;
        for (var i = 0; i < additional.Length; i++)
        {
            if (additional[i].Data is not OptionData data)
                continue;

            var updated = additional[i] with { Data = new OptionData(data.Options.Add(ede)) };
            return message with
            {
                Records = message.Records with { Additional = additional.SetItem(i, updated) }
            };
        }

        var opt = Create(infoCode);
        var appended = additional.IsDefaultOrEmpty ? ImmutableArray.Create(opt) : additional.Add(opt);
        return message with { Records = message.Records with { Additional = appended } };
    }

    public static DomainMessage CopyOntoServFail(DomainMessage request, DomainMessage source)
    {
        var message = DomainMessage.CreateResponse(
            request,
            DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure);
        foreach (var code in Codes(source))
            message = Attach(message, code);
        return message;
    }

    public static bool Contains(DomainMessage message, ushort infoCode)
    {
        foreach (var code in Codes(message))
        {
            if (code == infoCode)
                return true;
        }

        return false;
    }

    private static IEnumerable<ushort> Codes(DomainMessage message)
    {
        foreach (var record in message.Records.Additional)
        {
            if (record.Data is not OptionData data)
                continue;

            foreach (var option in data.Options)
            {
                if (option.Code != OptionCode || option.Data.Length < 2)
                    continue;

                yield return BinaryPrimitives.ReadUInt16BigEndian(option.Data.AsSpan());
            }
        }
    }

    private static byte[] Encode(ushort infoCode)
    {
        var data = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(data, infoCode);
        return data;
    }
}
