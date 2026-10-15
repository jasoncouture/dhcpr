using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Security.Cryptography;

using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol;

public sealed class EdnsLoopTag : IEdnsLoopTag
{
    public const ushort OptionCode = 65534;
    public const byte Version = 1;
    public const int TagLength = 16;

    /// <summary>
    /// A self-query returns in milliseconds. The cookie skew window is long
    /// enough for silos whose clocks differ, and short enough that a captured
    /// tag dies.
    /// </summary>
    public static readonly TimeSpan Lifetime = DnsServerCookieFactory.ClockSkew;

    private readonly IDnsServerCookieSecretSource _secrets;
    private readonly TimeProvider _time;

    public EdnsLoopTag(IDnsServerCookieSecretSource secrets, TimeProvider timeProvider)
    {
        _secrets = secrets;
        _time = timeProvider;
    }

    public void Ensure(DomainMessageContext context)
    {
        if (context.SelfQueryCookie is not null)
            return;
        if (TryCreate(context.DomainMessage, out var cookie))
            context.SelfQueryCookie = cookie;
    }

    public ImmutableArray<byte>? Share(DomainMessageContext parent, DomainMessage message)
    {
        if (!SameQuestion(parent.DomainMessage, message))
            return null;

        Ensure(parent);
        return parent.SelfQueryCookie;
    }

    public ImmutableArray<byte>? Create(DomainMessage message)
        => TryCreate(message, out var cookie) ? cookie : null;

    private bool TryCreate(DomainMessage message, out ImmutableArray<byte> cookie)
    {
        cookie = default;
        if (message.Questions.IsDefaultOrEmpty)
            return false;

        return TryCreate(message.Questions[0], out cookie);
    }

    public bool IsOurs(DomainMessage message)
    {
        if (message.Questions.IsDefaultOrEmpty)
            return false;

        var question = message.Questions[0];
        foreach (var record in message.Records.Additional)
        {
            if (record.Type is not DomainRecordType.OPT || record.Data is not OptionData data)
                continue;

            foreach (var option in data.Options)
            {
                if (option.Code == OptionCode && IsValid(question, option.Data.AsSpan()))
                    return true;
            }
        }

        return false;
    }

    private bool TryCreate(DomainQuestion question, out ImmutableArray<byte> cookie)
    {
        cookie = default;
        if (!_secrets.TryGetSecret(out var secret) || secret.Length < 16)
            return false;

        Span<byte> tag = stackalloc byte[TagLength];
        tag[0] = Version;
        var now = (uint)_time.GetUtcNow().ToUnixTimeSeconds();
        BinaryPrimitives.WriteUInt32BigEndian(tag[4..8], now);
        WriteHash(secret.Span, question, tag[..8], tag[8..]);
        cookie = ImmutableArray.Create(tag);
        return true;
    }

    private bool IsValid(DomainQuestion question, ReadOnlySpan<byte> tag)
    {
        if (tag.Length != TagLength || tag[0] != Version)
            return false;
        if (!_secrets.TryGetSecret(out var secret) || secret.Length < 16)
            return false;

        var timestamp = BinaryPrimitives.ReadUInt32BigEndian(tag[4..8]);
        var now = _time.GetUtcNow().ToUnixTimeSeconds();
        var age = now - timestamp;
        if (age > (long)Lifetime.TotalSeconds || age < -(long)DnsServerCookieFactory.ClockSkew.TotalSeconds)
            return false;

        Span<byte> expected = stackalloc byte[8];
        WriteHash(secret.Span, question, tag[..8], expected);
        return CryptographicOperations.FixedTimeEquals(expected, tag[8..]);
    }

    private static void WriteHash(
        ReadOnlySpan<byte> secret,
        DomainQuestion question,
        ReadOnlySpan<byte> header,
        Span<byte> destination)
    {
        // Class, type, canonical wire name, then the tag header (version and time).
        Span<byte> input = stackalloc byte[4 + 255 + 8];
        BinaryPrimitives.WriteUInt16BigEndian(input, (ushort)question.Class);
        BinaryPrimitives.WriteUInt16BigEndian(input[2..], (ushort)question.Type);
        var cursor = input[4..];
        DomainResourceRecordCanonicalizationExtensions.EncodeCanonicalName(ref cursor, question.Name);
        header.CopyTo(cursor);
        var length = input.Length - cursor.Length + header.Length;

        Span<byte> hash = stackalloc byte[32];
        HMACSHA256.HashData(secret, input[..length], hash);
        hash[..8].CopyTo(destination);
    }

    private static bool SameQuestion(DomainMessage left, DomainMessage right)
    {
        if (left.Questions.IsDefaultOrEmpty || right.Questions.IsDefaultOrEmpty)
            return false;

        var a = left.Questions[0];
        var b = right.Questions[0];
        return a.Type == b.Type && a.Class == b.Class && a.Name.Equals(b.Name);
    }
}
