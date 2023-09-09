using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Text;

using Dhcpr.Core;
using Dhcpr.Core.Linq;

namespace Dhcpr.Dns.Core.Protocol;

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
        var flags = ReadMessageFlagsAndAdvance(ref bytes);
        var questionCount = ReadUnsignedShortAndAdvance(ref bytes);

        var answerCount = ReadUnsignedShortAndAdvance(ref bytes);
        var authorityCount = ReadUnsignedShortAndAdvance(ref bytes);
        var additionalCount = ReadUnsignedShortAndAdvance(ref bytes);
        using var questions = GetQuestionsFromDataAndAdvance(ref bytes, questionCount);

        using var resourceRecords = ReadRecordsAndAdvance(ref bytes, answerCount + authorityCount + additionalCount);

        var domainResourceRecords = new DomainResourceRecords(
            resourceRecords.Take(answerCount).ToImmutableArray(),
            resourceRecords.Skip(answerCount).Take(authorityCount).ToImmutableArray(),
            resourceRecords.Skip(answerCount).Skip(authorityCount).ToImmutableArray()
        );

        return new DomainMessage(flags, questions.ToImmutableArray(), domainResourceRecords);
    }

    public static DomainMessageFlags ReadMessageFlagsAndAdvance(ref ReadOnlySpan<byte> bytes)
    {
        var id = ReadUnsignedShortAndAdvance(ref bytes);
        var flags = ReadUnsignedShortAndAdvance(ref bytes);

        if (!BitConverter.IsLittleEndian)
            flags = BinaryPrimitives.ReverseEndianness(flags);

        return new DomainMessageFlags(id,
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

    public static DomainLabels ReadLabelsAndAdvance(ref ReadOnlySpan<byte> bytes)
    {
        using var labels = ListPool<string>.Default.Get();
        while (true)
        {
            var nextCount = ReadByteAndAdvance(ref bytes);
            if (nextCount == 0) break;
            if (nextCount > 63)
                throw new InvalidDataException("Maximum label length is 63 bytes");
            if (nextCount > bytes.Length)
                throw new InvalidDataException("Unexpected end of data");
            var label = Encoding.ASCII.GetString(bytes[..nextCount]);
            labels.Add(label);
            bytes = bytes[nextCount..];
        }

        return new DomainLabels(labels);
    }

    public static PooledList<DomainResourceRecord> ReadRecordsAndAdvance(ref ReadOnlySpan<byte> bytes, int count)
    {
        var resourceRecords = ListPool<DomainResourceRecord>.Default.Get();
        for (var x = 0; x < count; x++)
        {
            resourceRecords.Add(ReadRecordAndAdvance(ref bytes));
        }

        return resourceRecords;
    }

    public static DomainResourceRecord ReadRecordAndAdvance(ref ReadOnlySpan<byte> bytes)
    {
        var labels = ReadLabelsAndAdvance(ref bytes);
        var type = (DomainRecordType)ReadUnsignedShortAndAdvance(ref bytes);
        var @class = (DomainRecordClass)ReadUnsignedShortAndAdvance(ref bytes);
        var ttl = ReadTimeSpanAndAdvance(ref bytes);
        var dataLength = ReadUnsignedShortAndAdvance(ref bytes);
        var dataBuffer = bytes[..dataLength];

        bytes = bytes[dataLength..];

        return new DomainResourceRecord(labels, type, @class, ttl, dataBuffer.ToImmutableArray());
    }

    public static PooledList<DomainQuestion> GetQuestionsFromDataAndAdvance(ref ReadOnlySpan<byte> bytes,
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

    public static int ReadIntegerAndAdvance(ref ReadOnlySpan<byte> bytes)
    {
        var decoded = BitConverter.ToInt32(bytes).ToHostByteOrder();
        bytes = bytes[4..];
        return decoded;
    }

    public static byte ReadByteAndAdvance(ref ReadOnlySpan<byte> bytes)
    {
        var ret = bytes[0];
        bytes = bytes[1..];
        return ret;
    }

    public static TimeSpan ReadTimeSpanAndAdvance(ref ReadOnlySpan<byte> bytes)
    {
        var totalSeconds = ReadIntegerAndAdvance(ref bytes);
        return TimeSpan.FromSeconds(totalSeconds);
    }

    public static ushort ReadUnsignedShortAndAdvance(ref ReadOnlySpan<byte> bytes)
    {
        var decoded = BitConverter.ToUInt16(bytes).ToHostByteOrder();
        bytes = bytes[2..];
        return decoded;
    }

    public static void Encode(Span<byte> buffer, DomainMessage message)
    {
        EncodeAndAdvance(ref buffer, message.Flags);
        EncodeAndAdvance(ref buffer, (ushort)message.Questions.Length);
        EncodeAndAdvance(ref buffer, (ushort)message.Records.Answers.Length);
        EncodeAndAdvance(ref buffer, (ushort)message.Records.Authorities.Length);
        EncodeAndAdvance(ref buffer, (ushort)message.Records.Additional.Length);
        EncodeAndAdvance(ref buffer, message.Questions);
        EncodeAndAdvance(ref buffer, message.Records);
    }

    public static void EncodeAndAdvance(ref Span<byte> buffer, TimeSpan timeSpan)
    {
        EncodeAndAdvance(ref buffer, (int)timeSpan.TotalSeconds);
    }

    public static void EncodeAndAdvance(ref Span<byte> buffer, DomainResourceRecords records)
    {
        foreach (var record in records)
        {
            EncodeAndAdvance(ref buffer, record);
        }
    }

    public static void EncodeAndAdvance(ref Span<byte> buffer, DomainResourceRecord record)
    {
        EncodeAndAdvance(ref buffer, record.Name);
        EncodeAndAdvance(ref buffer, (ushort)record.Type);
        EncodeAndAdvance(ref buffer, (ushort)record.Class);
        EncodeAndAdvance(ref buffer, (int)record.TimeToLive.TotalSeconds);
        EncodeAndAdvance(ref buffer, (ushort)record.Data.Length);
        record.Data.CopyTo(buffer);
        buffer = buffer[record.Data.Length..];
    }

    public static void EncodeAndAdvance(ref Span<byte> buffer, int value)
    {
        BitConverter.TryWriteBytes(buffer, value.ToNetworkByteOrder());
        buffer = buffer[sizeof(int)..];
    }

    public static void EncodeAndAdvance(ref Span<byte> buffer, ImmutableArray<DomainQuestion> questions)
    {
        foreach (var question in questions)
        {
            EncodeAndAdvance(ref buffer, question);
        }
    }

    public static void EncodeAndAdvance(ref Span<byte> buffer, DomainQuestion question)
    {
        EncodeAndAdvance(ref buffer, question.Name);
        EncodeAndAdvance(ref buffer, (ushort)question.Type);
        EncodeAndAdvance(ref buffer, (ushort)question.Class);
    }

    public static void EncodeAndAdvance(ref Span<byte> buffer, DomainLabels labels)
    {
        foreach (var label in labels.Labels)
        {
            EncodeAndAdvance(ref buffer, label);
        }
        EncodeAndAdvance(ref buffer, DomainLabel.Empty);
    }

    public static void EncodeAndAdvance(ref Span<byte> bytes, byte value)
    {
        bytes[0] = value;
        bytes = bytes[1..];
    }

    public static void EncodeAndAdvance(ref Span<byte> buffer, string value)
    {
        Encoding.ASCII.GetBytes(value, buffer);
        buffer = buffer[value.Length..];
    }

    public static void EncodeAndAdvance(ref Span<byte> buffer, DomainLabel label)
    {
        EncodeAndAdvance(ref buffer, (byte)label.Label.Length);
        EncodeAndAdvance(ref buffer, label.Label);
    }

    public static void EncodeAndAdvance(ref Span<byte> buffer, ushort value)
    {
        BitConverter.TryWriteBytes(buffer, value.ToNetworkByteOrder());
        buffer = buffer[2..];
    }

    public static void EncodeAndAdvance(ref Span<byte> buffer, DomainMessageFlags messageFlags)
    {
        if (buffer.Length < messageFlags.Size) throw new ArgumentException("Buffer size is too small.");
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

        if (!BitConverter.IsLittleEndian)
            flags = BinaryPrimitives.ReverseEndianness(flags);

        EncodeAndAdvance(ref buffer, messageFlags.Id);
        EncodeAndAdvance(ref buffer, flags);
    }
}