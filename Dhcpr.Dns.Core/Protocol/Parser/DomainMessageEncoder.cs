using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Parser;

public static class DomainMessageEncoder
{
    private const int MinimumSize = 12;

    // RD - bit 15
    private const int ResponseBitIndex = 15;

    // OpCode - bit 10-14
    private const int OperationCodeBitIndex = 11;

    // AA - Bit 9
    private const int AuthorativeBitIndex = 10;

    // TC - Bit 8
    private const int TruncatedBitIndex = 9;

    // RD - Bit 7
    private const int RecursionDesiredBitIndex = 8;

    // RA - Bit 7
    private const int RecursionAvailableBitIndex = 7;

    // Zero - Bit 6,5,4 (Not really)
    // Authentic = bit 5
    private const int AuthenticBitIndex = 5;

    // Checking Disabled = bit 4
    private const int CheckingDisabledBitIndex = 4;

    // Response code = bits 0-3
    private const int ResponseCodeBitIndex = 0;

    private const int ResponseCodeBitCount = 4;
    private const int OperationCodeBitCount = 4;

    public static DomainMessage Decode(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < MinimumSize)
            throw new ArgumentException("Domain messages require at least 12 bytes of data.");
        using var labels = DictionaryPool<int, string>.Default.Get();
        var parsingSpan = new ReadOnlyDnsParsingSpan(bytes);
        var id = ReadUnsignedShortAndAdvance(ref parsingSpan);
        var flags = ReadMessageFlagsAndAdvance(ref parsingSpan);

        var questionCount = ReadUnsignedShortAndAdvance(ref parsingSpan);
        var answerCount = ReadUnsignedShortAndAdvance(ref parsingSpan);
        var authorityCount = ReadUnsignedShortAndAdvance(ref parsingSpan);
        var additionalCount = ReadUnsignedShortAndAdvance(ref parsingSpan);
        using var questions = GetQuestionsFromDataAndAdvance(ref parsingSpan, questionCount);

        using var resourceRecords =
            ReadRecordsAndAdvance(ref parsingSpan, answerCount + authorityCount + additionalCount);

        var domainResourceRecords = new DomainResourceRecords(
            resourceRecords.Take(answerCount).ToImmutableArray(),
            resourceRecords.Skip(answerCount).Take(authorityCount).ToImmutableArray(),
            resourceRecords.Skip(answerCount).Skip(authorityCount).ToImmutableArray()
        );

        return new DomainMessage(id, flags, questions.ToImmutableArray(), domainResourceRecords);
    }

    public static DomainMessageFlags ReadMessageFlagsAndAdvance(ref ReadOnlyDnsParsingSpan bytes)
    {
        var flags = ReadUnsignedShortAndAdvance(ref bytes);

        return new DomainMessageFlags(
            ReadBit(flags, ResponseBitIndex),
            (DomainOperationCode)ReadBits(flags, OperationCodeBitIndex, OperationCodeBitCount),
            ReadBit(flags, AuthorativeBitIndex),
            ReadBit(flags, TruncatedBitIndex),
            ReadBit(flags, RecursionDesiredBitIndex),
            ReadBit(flags, RecursionAvailableBitIndex),
            ReadBit(flags, AuthenticBitIndex),
            ReadBit(flags, CheckingDisabledBitIndex),
            (DomainResponseCode)ReadBits(flags, ResponseCodeBitIndex, ResponseCodeBitCount)
        );
    }

    public static DomainLabels ReadLabelsAndAdvance(ref ReadOnlyDnsParsingSpan bytes)
    {
        using var visitedPositions = Pool.GetHashSet<int>();
        using var labels = ReadLabelArrayAndAdvance(ref bytes, visitedPositions);
        return new DomainLabels(labels.ToImmutableArray());
    }

    private const ushort DnsCompressionFlag = 0xC000;
    private const ushort DnsCompressionFlagMask = (DnsCompressionFlag ^ 0xFFFF) & 0xFFFF;

    private static void VisitPosition(int offset, HashSet<int> visitedPositions)
    {
        if (!visitedPositions.Add(offset))
            throw new InvalidDataException("DNS compression loop detected.");
    }
    // No, it can't be. :|
    [SuppressMessage("ReSharper", "ReturnTypeCanBeEnumerable.Local")]
    private static PooledList<DomainLabel> ReadLabelArrayAndAdvance(ref ReadOnlyDnsParsingSpan bytes,
        HashSet<int> visitedPositions)
    {
        var labelPool = ListPool<DomainLabel>.Default.Get();
        var targetBytes = bytes;
        bool encounteredPointer = false;
        while (true)
        {
            VisitPosition(targetBytes.Offset, visitedPositions);
            var nextCount = ReadByteAndAdvance(ref targetBytes);
            switch (nextCount)
            {
                case 0:
                    if (!encounteredPointer)
                        bytes = targetBytes;
                    return labelPool;
                case < 192 and > 63:
                    throw new InvalidDataException("Maximum label length is 63 bytes");
                case <= 63:
                    labelPool.Add(new DomainLabel(Encoding.ASCII.GetString(targetBytes[..nextCount])));
                    targetBytes = targetBytes[nextCount..];
                    break;
                case >= 192:

                    targetBytes = targetBytes.Start[(targetBytes.Offset - 1)..];
                    var pointerOffset = ReadUnsignedShortAndAdvance(ref targetBytes);
                    pointerOffset &= DnsCompressionFlagMask;
                    if (!encounteredPointer)
                    {
                        bytes = targetBytes;
                        encounteredPointer = true;
                    }
                    targetBytes = targetBytes.Start[pointerOffset..];
                    break;
            }

            if (!encounteredPointer)
                bytes = targetBytes;
        }
    }


    public static PooledList<DomainResourceRecord> ReadRecordsAndAdvance(ref ReadOnlyDnsParsingSpan bytes, int count)
    {
        var resourceRecords = ListPool<DomainResourceRecord>.Default.Get();

        for (var x = 0; x < count; x++)
        {
            resourceRecords.Add(ReadRecordAndAdvance(ref bytes));
        }

        return resourceRecords;
    }

    public static DomainResourceRecord ReadRecordAndAdvance(ref ReadOnlyDnsParsingSpan bytes)
    {
        var labels = ReadLabelsAndAdvance(ref bytes);
        var type = (DomainRecordType)ReadUnsignedShortAndAdvance(ref bytes);
        var @class = (DomainRecordClass)ReadUnsignedShortAndAdvance(ref bytes);
        var ttl = ReadTimeSpanAndAdvance(ref bytes);
        var dataLength = ReadUnsignedShortAndAdvance(ref bytes);
        var dataBuffer = bytes[..dataLength];
        var ret = new DomainResourceRecord(labels, type, @class, ttl, dataBuffer.ToData(type, dataLength));
        bytes = bytes[dataLength..];

        return ret;
    }

    public static PooledList<DomainQuestion> GetQuestionsFromDataAndAdvance(ref ReadOnlyDnsParsingSpan bytes,
        ushort questionCount)
    {
        PooledList<DomainQuestion> questionPooledList = ListPool<DomainQuestion>.Default.Get();
        for (var x = 0; x < questionCount; x++)
        {
            var labels = ReadLabelsAndAdvance(ref bytes);
            var questionType = ReadUnsignedShortAndAdvance(ref bytes);
            var questionClass = ReadUnsignedShortAndAdvance(ref bytes);
            questionPooledList.Add(new DomainQuestion(labels, (DomainRecordType)questionType,
                (DomainRecordClass)questionClass));
        }

        return questionPooledList;
    }

    public static readonly int[] BitMaskLookup = new[]
    {
        0b0000000000000000, 0b0000000000000001, 0b0000000000000011, 0b0000000000000111, 0b0000000000001111,
        0b0000000000011111, 0b0000000000111111, 0b0000000001111111, 0b0000000011111111, 0b0000000111111111,
        0b0000001111111111, 0b0000011111111111, 0b0000111111111111, 0b0001111111111111, 0b0011111111111111,
        0b0111111111111111, 0b1111111111111111
    };

    public static bool ReadBit(ushort input, int bitIndex)
    {
        return ReadBits(input, bitIndex, 1) != 0;
    }

    public static ushort ReadBits(ushort input, int bitIndex, int bitCount)
    {
        if (bitIndex > 15) throw new ArgumentOutOfRangeException(nameof(bitIndex));
        if (bitCount == 0 || bitCount > 16 || bitCount + bitIndex > 16)
            throw new ArgumentOutOfRangeException(nameof(bitCount));
        var mask = BitMaskLookup[bitCount];
        input = (ushort)(input >>> bitIndex);
        return (ushort)(input & mask);
    }

    public static void SetBit(ref ushort input, bool value, int bitIndex)
    {
        SetBits(ref input, (ushort)(value ? 1 : 0), bitIndex, 1);
    }

    public static void SetBits(ref ushort input, ushort value, int bitIndex, int bitCount)
    {
        if (bitIndex > 15) throw new ArgumentOutOfRangeException(nameof(bitIndex));
        if (bitCount == 0 || bitCount > 16 || bitCount + bitIndex > 16)
            throw new ArgumentOutOfRangeException(nameof(bitCount));
        var mask = (ushort)BitMaskLookup[bitCount];
        value <<= bitIndex;
        mask <<= bitIndex;
        value &= mask;

        input = (ushort)((input & ~mask) | value);
    }

    public static int ReadIntegerAndAdvance(ref ReadOnlyDnsParsingSpan bytes)
    {
        var decoded = BitConverter.ToInt32(bytes).ToHostByteOrder();
        bytes = bytes[4..];
        return decoded;
    }

    public static byte ReadByteAndAdvance(ref ReadOnlyDnsParsingSpan bytes)
    {
        var ret = bytes[0];
        bytes = bytes[1..];
        return ret;
    }

    public static TimeSpan ReadTimeSpanAndAdvance(ref ReadOnlyDnsParsingSpan bytes)
    {
        var totalSeconds = ReadIntegerAndAdvance(ref bytes);
        return TimeSpan.FromSeconds(totalSeconds);
    }

    public static ushort ReadUnsignedShortAndAdvance(ref ReadOnlyDnsParsingSpan bytes)
    {
        var decoded = BitConverter.ToUInt16(bytes).ToHostByteOrder();
        bytes = bytes[2..];
        return decoded;
    }

    public static int Encode(Span<byte> buffer, DomainMessage message)
    {
        using var pooledLabelDictionary = DictionaryPool<string, int>.Default.Get();
        var dnsParsingSpan = new DnsParsingSpan(pooledLabelDictionary, buffer);
        var startOffset = dnsParsingSpan.Offset;
        EncodeAndAdvance(ref dnsParsingSpan, message.Id);
        EncodeAndAdvance(ref dnsParsingSpan, message.Flags);
        EncodeAndAdvance(ref dnsParsingSpan, (ushort)message.Questions.Length);
        EncodeAndAdvance(ref dnsParsingSpan, (ushort)message.Records.Answers.Length);
        EncodeAndAdvance(ref dnsParsingSpan, (ushort)message.Records.Authorities.Length);
        EncodeAndAdvance(ref dnsParsingSpan, (ushort)message.Records.Additional.Length);
        EncodeAndAdvance(ref dnsParsingSpan, message.Questions);
        EncodeAndAdvance(ref dnsParsingSpan, message.Records);
        return dnsParsingSpan.Offset - startOffset;
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan buffer, TimeSpan timeSpan)
    {
        EncodeAndAdvance(ref buffer, (int)timeSpan.TotalSeconds);
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan buffer, DomainResourceRecords records)
    {
        foreach (var record in records)
        {
            EncodeAndAdvance(ref buffer, record);
        }
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan buffer, DomainResourceRecord record)
    {
        EncodeAndAdvance(ref buffer, record.Name);
        EncodeAndAdvance(ref buffer, (ushort)record.Type);
        EncodeAndAdvance(ref buffer, (ushort)record.Class);
        EncodeAndAdvance(ref buffer, (int)record.TimeToLive.TotalSeconds);
        EncodeAndAdvance(ref buffer, record.Data);
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan buffer, IDomainResourceRecordData data)
    {
        data.WriteTo(ref buffer);
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan buffer, int value)
    {
        BitConverter.TryWriteBytes(buffer, value.ToNetworkByteOrder());
        buffer = buffer[sizeof(int)..];
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan buffer, ImmutableArray<DomainQuestion> questions)
    {
        foreach (var question in questions)
        {
            EncodeAndAdvance(ref buffer, question);
        }
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan buffer, DomainQuestion question)
    {
        EncodeAndAdvance(ref buffer, question.Name);
        EncodeAndAdvance(ref buffer, (ushort)question.Type);
        EncodeAndAdvance(ref buffer, (ushort)question.Class);
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan buffer, DomainLabels labels)
    {
        for (var index = 0; index < labels.Labels.Length; index++)
        {
            var slice = labels.Labels[index..];
            var currentFullLabel = string.Join('.', slice);
            if (buffer.TryGetOffset(currentFullLabel, out var offset))
            {
                EncodeAndAdvance(ref buffer, (ushort)((offset & ushort.MaxValue) | DnsCompressionFlag));
                return;
            }

            buffer.AddLabel(currentFullLabel, buffer.Offset);
            EncodeAndAdvance(ref buffer, labels.Labels[index]);
        }

        EncodeAndAdvance(ref buffer, (byte)0);
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan bytes, byte value)
    {
        bytes.Span[0] = value;
        bytes = bytes[1..];
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan buffer, string value)
    {
        Encoding.ASCII.GetBytes(value, buffer);
        buffer = buffer[value.Length..];
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan buffer, DomainLabel label)
    {
        if (label.Label.Length > 63) throw new InvalidDataException("Labels can only be up to 63 bytes.");
        EncodeAndAdvance(ref buffer, (byte)label.Label.Length);
        EncodeAndAdvance(ref buffer, label.Label);
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan buffer, ushort value)
    {
        BitConverter.TryWriteBytes(buffer, value.ToNetworkByteOrder());
        buffer = buffer[2..];
    }

    public static void EncodeAndAdvance(ref DnsParsingSpan buffer, DomainMessageFlags messageFlags)
    {
        if (buffer.Count < messageFlags.EstimatedSize)
            throw new ArgumentException("Buffer size is too small.");

        ushort flags = 0;
        SetBit(ref flags, messageFlags.Response, ResponseBitIndex);
        SetBits(ref flags, (ushort)messageFlags.Operation, OperationCodeBitIndex, OperationCodeBitCount);
        SetBit(ref flags, messageFlags.Authorative, AuthorativeBitIndex);
        SetBit(ref flags, messageFlags.Truncated, TruncatedBitIndex);
        SetBit(ref flags, messageFlags.RecursionDesired, RecursionDesiredBitIndex);
        SetBit(ref flags, messageFlags.RecursionAvailable, RecursionAvailableBitIndex);
        SetBit(ref flags, messageFlags.Authentic, AuthenticBitIndex);
        SetBit(ref flags, messageFlags.CheckingDisabled, CheckingDisabledBitIndex);
        SetBits(ref flags, (ushort)messageFlags.ResponseCode, ResponseCodeBitIndex, ResponseCodeBitCount);

        EncodeAndAdvance(ref buffer, flags);
    }
}