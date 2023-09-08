using System.Buffers;
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
    HardwareAddressType HardwareAddressType,
    byte HardwareAddressLength,
    byte Hops,
    int TransactionId,
    ushort Seconds,
    DhcpFlags Flags,
    IPAddress ClientAddress,
    IPAddress YourAddress,
    IPAddress ServerAddress,
    IPAddress RelayAddress,
    HardwareAddress ClientHardwareAddress,
    string ServerName,
    string BootFileName,
    DhcpOptionCollection Options
)
{
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
    public int Size => BaseSize + OptionsSize;


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

        var clientHardwareAddress = span[..ClientHardwareAddressMaxLength];
        span = span[ClientHardwareAddressMaxLength..];
        
        var serverNameBytes = span[..ServerNameMaxLength];
        span = span[ServerNameMaxLength..];
        
        var bootFileNameBytes = span[..BootFileNameMaxLength];
        span = span[BootFileNameMaxLength..];

        var magicCookie = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(span[..sizeof(int)]));
        if (magicCookie != MagicCookie) return false; // Maybe it's BOOTP?
        span = span[sizeof(int)..];

        using var pooledList = EnumerateOptions(span).ToPooledList();
        if (pooledList.Any(i => i.Item1 == false)) return false;

        var serverName = ParseFixedLengthString(serverNameBytes);
        var bootFileName = ParseFixedLengthString(bootFileNameBytes);

        message = new DhcpMessage(
            opCode, hardwareAddressType, hardwareAddressLength, hops,
            transactionId,
            seconds, flags,
            addresses[0],
            addresses[1],
            addresses[2],
            addresses[3],
            new HardwareAddress(clientHardwareAddress.ToImmutableArray(), hardwareAddressLength),
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
        WriteAndAdvance(ref buffer, (byte)HardwareAddressType);
        WriteAndAdvance(ref buffer, HardwareAddressLength);
        WriteAndAdvance(ref buffer, Hops);
        
        WriteAndAdvance(ref buffer, TransactionId);
        
        WriteAndAdvance(ref buffer, Seconds);
        WriteAndAdvance(ref buffer, (ushort)Flags);
        
        
        WriteAndAdvance(ref buffer, ClientAddress);
        WriteAndAdvance(ref buffer, YourAddress);
        WriteAndAdvance(ref buffer, ServerAddress);
        WriteAndAdvance(ref buffer, RelayAddress);
        
        ClientHardwareAddress.WriteAndAdvance(ref buffer);
        
        WriteAndAdvance(ref buffer, ServerName, ServerNameMaxLength);
        
        WriteAndAdvance(ref buffer, BootFileName, BootFileNameMaxLength);
        
        WriteAndAdvance(ref buffer, MagicCookie);
        foreach (var option in Options)
        {
            option.WriteAndAdvance(ref buffer);
        }
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