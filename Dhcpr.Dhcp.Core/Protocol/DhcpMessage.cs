using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Text;

using Dhcpr.Core;
using Dhcpr.Core.Linq;

namespace Dhcpr.Dhcp.Core.Protocol;

public record DhcpMessage(
    BootOperationCode OperationCode,
    byte Hops,
    int TransactionId,
    ushort Seconds,
    DhcpFlags Flags,
    IPAddress ClientAddress,
    IPAddress YourAddress,
    IPAddress ServerAddress,
    IPAddress RelayAddress,
    HardwareAddress HardwareAddress,
    string ServerName,
    string BootFileName,
    DhcpOptionCollection Options
)
{
    static DhcpMessage()
    {
        Template = new DhcpMessage(BootOperationCode.Response, 0, 0, 0, DhcpFlags.None,
            IPAddress.Any, IPAddress.Any, IPAddress.Any, IPAddress.Any,
            new HardwareAddress(ImmutableArray<byte>.Empty, HardwareAddressType.Reserved, 0), string.Empty,
            string.Empty,
            DhcpOptionCollection.Empty);
    }

    public static DhcpMessage Template { get; }
    private const int ClientHardwareAddressMaxLength = 16;
    private const int ServerNameMaxLength = 64;
    private const int BootFileNameMaxLength = 128;
    private const int IPAddressSize = 4;

    private const int BaseSize =
        sizeof(BootOperationCode) +
        sizeof(HardwareAddressType) +
        (sizeof(byte) * 2) +
        sizeof(int) +
        sizeof(ushort) +
        sizeof(DhcpFlags) +
        (IPAddressSize * 4) +
        ClientHardwareAddressMaxLength +
        ServerNameMaxLength +
        BootFileNameMaxLength +
        sizeof(int); // Magic Cookie

    private int? _optionsSize;
    private const int MagicCookie = 0x63825363;
    public int OptionsSize => _optionsSize ??= Options.Select(i => i.Length).DefaultIfEmpty(0).Sum();
    public int Size => BaseSize + Options.Length;


    public static bool TryParse(ReadOnlySpan<byte> span, [NotNullWhen(true)] out DhcpMessage? message)
    {
        message = null;
        if (span.Length < BaseSize) return false;
        var opCode = (BootOperationCode)span[0];
        var hardwareAddressType = (HardwareAddressType)span[1];
        var hardwareAddressLength = span[2];
        if (hardwareAddressLength > 16) return false;
        if (hardwareAddressLength == 0) return false;
        var hops = span[3];

        span = span[4..];
        var transactionId = BitConverter.ToInt32(span[..4]).ToHostByteOrder();

        span = span[4..];
        ushort seconds = BitConverter.ToUInt16(span[..2]).ToHostByteOrder();

        span = span[2..];
        var flags = (DhcpFlags)BitConverter.ToUInt16(span[..2]).ToHostByteOrder();

        span = span[2..];
        var addresses = new IPAddress[4];
        for (var i = 0; i < 4; i++)
        {
            var nextAddress = new IPAddress(span[..4]);
            span = span[4..];
            addresses[i] = nextAddress;
        }

        var hardwareAddressSpan = span;
        span = span[HardwareAddress.HardwareAddressMaxLength..];

        var serverNameBytes = span[..ServerNameMaxLength];
        span = span[ServerNameMaxLength..];

        var bootFileNameBytes = span[..BootFileNameMaxLength];
        span = span[BootFileNameMaxLength..];

        var magicCookie = BitConverter.ToInt32(span[..sizeof(int)]).ToHostByteOrder();
        if (magicCookie != MagicCookie) return false; // Maybe it's BOOTP?
        span = span[sizeof(int)..];

        using var pooledList = EnumerateOptions(span).ToPooledList();
        if (pooledList.Any(i => i.Item1 == false)) return false;
        // We avoid allocating heap memory when we fail to parse by waiting until all validation passes to create
        // any objects we can defer until now.
        var serverName = ParseFixedLengthString(serverNameBytes);
        var bootFileName = ParseFixedLengthString(bootFileNameBytes);
        var clientHardwareAddress =
            HardwareAddress.ReadAndAdvance(ref hardwareAddressSpan, hardwareAddressType, hardwareAddressLength);

        message = new DhcpMessage(
            opCode, hops,
            transactionId,
            seconds, flags,
            addresses[0],
            addresses[1],
            addresses[2],
            addresses[3],
            clientHardwareAddress,
            serverName,
            bootFileName,
            new DhcpOptionCollection(pooledList.Select(i => i.Item2!).ToImmutableArray()));

        return true;
    }

    private static string ParseFixedLengthString(ReadOnlySpan<byte> span)
    {
        // Strip trailing nulls
        while (span.Length > 0)
        {
            if (span[^1] != 0)
                break;
            span = span[..^1];
        }

        return Encoding.ASCII.GetString(span);
    }

    private static IEnumerable<(bool, DhcpOption?)> EnumerateOptions(ReadOnlySpan<byte> span)
    {
        List<(bool, DhcpOption?)> options = new();
        while (span.Length > 0)
        {
            var status = DhcpOption.TryParse(span, out var dhcpOption);
            options.Add((status, dhcpOption));
            if (!status) break;
            span = span[dhcpOption!.Length..];
        }

        return options;
    }

    public void EncodeTo(byte[] buffer)
    {
        Span<byte> internalBuffer = stackalloc byte[Size];
        EncodeTo(internalBuffer);
        internalBuffer.CopyTo(buffer);
    }

    public void EncodeTo(Span<byte> buffer)
    {
        // Unclear if these can occupy the last byte, or the last byte must be null.
        // So, safe side. On the plus side, it may help protect clients that have exploits in their
        // DHCP Client stack here.
        if (ServerName.Length > ServerNameMaxLength - 1)
            throw new InvalidOperationException(
                $"Server name is too long. Server name can be up to {ServerNameMaxLength - 1}");
        if (BootFileName.Length > BootFileNameMaxLength - 1)
            throw new InvalidOperationException(
                $"Boot filename is too long. Boot file name can be up to {BootFileNameMaxLength - 1}");

        if (ClientAddress.AddressFamily != AddressFamily.InterNetwork ||
            YourAddress.AddressFamily != AddressFamily.InterNetwork ||
            ServerAddress.AddressFamily != AddressFamily.InterNetwork ||
            RelayAddress.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new InvalidOperationException("IP Addresses must be IPv4 only");
        }

        if (buffer.Length < Size) throw new ArgumentException("Insufficient buffer size", nameof(buffer));
        WriteAndAdvance(ref buffer, (byte)OperationCode);
        WriteAndAdvance(ref buffer, (byte)HardwareAddress.Type);
        WriteAndAdvance(ref buffer, (byte)HardwareAddress.Length);
        WriteAndAdvance(ref buffer, Hops);

        WriteAndAdvance(ref buffer, TransactionId);

        WriteAndAdvance(ref buffer, Seconds);
        WriteAndAdvance(ref buffer, (ushort)Flags);


        WriteAndAdvance(ref buffer, ClientAddress);
        WriteAndAdvance(ref buffer, YourAddress);
        WriteAndAdvance(ref buffer, ServerAddress);
        WriteAndAdvance(ref buffer, RelayAddress);

        HardwareAddress.WriteAndAdvance(ref buffer);

        WriteAndAdvance(ref buffer, ServerName, ServerNameMaxLength);

        WriteAndAdvance(ref buffer, BootFileName, BootFileNameMaxLength);

        WriteAndAdvance(ref buffer, MagicCookie);
        Options.WriteAndAdvance(ref buffer, includeEndMarker: true);
    }

    private void WriteAndAdvance(ref Span<byte> buffer, IPAddress address)
    {
        address.TryWriteBytes(buffer, out _);
        buffer = buffer[IPAddressSize..];
    }

    private void WriteAndAdvance(ref Span<byte> buffer, string str, int fixedLength)
    {
        Span<byte> stringBuffer = stackalloc byte[fixedLength];
        Encoding.ASCII.GetBytes(str, stringBuffer);
        stringBuffer.CopyTo(buffer);
        buffer = buffer[fixedLength..];
    }

    private void WriteAndAdvance(ref Span<byte> buffer, ushort u)
    {
        BitConverter.TryWriteBytes(buffer, u.ToNetworkByteOrder());
        buffer = buffer[sizeof(ushort)..];
    }

    private void WriteAndAdvance(ref Span<byte> buffer, int i)
    {
        BitConverter.TryWriteBytes(buffer, i.ToNetworkByteOrder());
        buffer = buffer[sizeof(int)..];
    }

    private static void WriteAndAdvance(ref Span<byte> buffer, byte b)
    {
        buffer[0] = b;
        buffer = buffer[sizeof(byte)..];
    }
}