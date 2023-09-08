using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Text;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dhcp.Core.Protocol;

namespace Dhcpr.Dhcp.Core.Client;

public record DhcpClientLease(
    HardwareAddress HardwareAddress,
    int TransactionId,
    IPNetwork Network,
    DateTimeOffset Created,
    DateTimeOffset ExpiresAt,
    DhcpClientState State,
    int OriginalTimeToLive,
    IPAddress Address,
    IPAddress Gateway,
    ImmutableArray<IPAddress> NameServers,
    DhcpOptionCollection AdditionalOptions,
    DhcpMessage? MessageTemplate = null,
    string? DomainName = null,
    string? HostName = null
)
{
    private void AddOptionIfSet(List<DhcpOption> options, DhcpOptionCode code, IPAddress address)
    {
        if (address.Equals(IPAddress.Any))
            return;
        if (address.AddressFamily != AddressFamily.InterNetwork)
            return;
        if (ContainsOption(options, code))
            return;
        Span<byte> addressBytes = stackalloc byte[4];
        address.TryWriteBytes(addressBytes, out _);
        options.Add(new DhcpOption(code, addressBytes.ToImmutableArray()));
    }

    private void AddOptionIfSet(List<DhcpOption> options, DhcpOptionCode code, IReadOnlyList<IPAddress> addresses)
    {
        if (addresses.Count == 0)
            return;
        if (addresses.Any(i => i.AddressFamily != AddressFamily.InterNetwork))
            return;
        if (ContainsOption(options, code))
            return;
        Span<byte> addressArrayBytes = stackalloc byte[addresses.Count * 4];
        for (var x = 0; x < addresses.Count; x++)
        {
            addresses[x].TryWriteBytes(addressArrayBytes[(x * 4)..4], out _);
        }

        options.Add(new DhcpOption(code, addressArrayBytes.ToImmutableArray()));
    }

    private void AddOptionIfSet(List<DhcpOption> options, DhcpOptionCode code, byte value)
    {
        if (value == 0) return;
        if (ContainsOption(options, code)) return;
        options.Add(new DhcpOption(code, value));
    }

    private void AddOptionIfSet(List<DhcpOption> options, DhcpOptionCode code, int value)
    {
        if (value == 0) return;
        if (ContainsOption(options, code))
            return;
        Span<byte> valueBytes = stackalloc byte[4];
        BitConverter.TryWriteBytes(valueBytes, value.ToNetworkByteOrder());
        options.Add(new DhcpOption(code, valueBytes.ToImmutableArray()));
    }

    private bool ContainsOption(List<DhcpOption> options, DhcpOptionCode code)
    {
        return options.Any(i => i.Code == code);
    }

    private void AddOptionIfSet(List<DhcpOption> options, DhcpOptionCode code, string? str)
    {
        if (string.IsNullOrWhiteSpace(str))
            return;
        if (ContainsOption(options, code))
            return;
        Span<byte> stringBytes = stackalloc byte[Encoding.ASCII.GetMaxByteCount(str.Length) + 1];
        var byteCount = Encoding.ASCII.GetBytes(str, stringBytes);
        stringBytes[byteCount] = 0;
        options.Add(new DhcpOption(code, stringBytes[..(byteCount + 1)].ToImmutableArray()));
    }

    public DhcpMessage ToDhcpMessageTemplate(DhcpMessageType messageType,
        IEnumerable<DhcpOptionCode>? allowedOptionCodes = null)
    {
        using var pooledOptionList = AdditionalOptions.ToPooledList();
        if (MessageTemplate is not null)
        {
            pooledOptionList.AddRange(MessageTemplate.Options.Where(i =>
                i.Code != DhcpOptionCode.End && i.Code != DhcpOptionCode.Pad));
        }

        AddOptionIfSet(pooledOptionList, DhcpOptionCode.DhcpMessageType, (byte)messageType);
        AddOptionIfSet(pooledOptionList, DhcpOptionCode.DomainName, DomainName);
        AddOptionIfSet(pooledOptionList, DhcpOptionCode.Hostname, HostName);
        AddOptionIfSet(pooledOptionList, DhcpOptionCode.DomainServer, NameServers);
        AddOptionIfSet(pooledOptionList, DhcpOptionCode.Router, Gateway);
        AddOptionIfSet(pooledOptionList, DhcpOptionCode.DhcpServerId, Network.Address);
        AddOptionIfSet(pooledOptionList, DhcpOptionCode.SubnetMask, Network.NetworkMask);
        AddOptionIfSet(pooledOptionList, DhcpOptionCode.BroadcastAddress, Network.BroadcastAddress);
        AddOptionIfSet(pooledOptionList, DhcpOptionCode.AddressLeaseTime, OriginalTimeToLive);


        var optionCodeHashSet = allowedOptionCodes?.ToHashSet();
        optionCodeHashSet?.Add(DhcpOptionCode.AddressLeaseTime);
        optionCodeHashSet?.Add(DhcpOptionCode.DhcpMessageType);
        optionCodeHashSet?.Add(DhcpOptionCode.DhcpServerId);
        optionCodeHashSet?.Add(DhcpOptionCode.End);

        var optionCollection =
            new DhcpOptionCollection(pooledOptionList.Where(i => optionCodeHashSet?.Contains(i.Code) ?? true));

        var finalTemplate = (MessageTemplate ?? DhcpMessage.Template) with
        {
            OperationCode = BootOperationCode.Response,
            TransactionId = TransactionId,
            HardwareAddress = HardwareAddress,
            ServerAddress = Network.Address,
            YourAddress = Address,
            Options = optionCollection
        };

        return finalTemplate;
    }

    public DhcpMessage ToDhcpMessageTemplate(DhcpMessageType messageType, DhcpMessage? incomingMessage)
    {
        if (incomingMessage is null)
        {
            return ToDhcpMessageTemplate(messageType);
        }

        var parameterRequestList = incomingMessage.Options.GetOptionForCode(DhcpOptionCode.ParameterRequestList);
        var ret = ToDhcpMessageTemplate(messageType, parameterRequestList?.Payload.Select(i => (DhcpOptionCode)i));

        if (incomingMessage.Flags != DhcpFlags.Broadcast && !incomingMessage.ClientAddress.Equals(IPAddress.Any))
        {
            ret = ret with { ClientAddress = incomingMessage.ClientAddress };
        }

        return ret;
    }
}