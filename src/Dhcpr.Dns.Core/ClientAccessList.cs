using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

namespace Dhcpr.Dns.Core;

/// <summary>
/// Client CIDR/IP allow-list. Empty <see cref="Networks"/> means any client (including unknown).
/// </summary>
public sealed record ClientAccessList(IPNetwork[] Networks)
{
    public static ClientAccessList Unrestricted { get; } = new([]);

    public bool IsRestricted => Networks.Length > 0;

    public bool AllowsClient(IPAddress? client)
    {
        if (Networks.Length == 0)
            return true;
        if (client is null)
            return false;

        var address = client.IsIPv4MappedToIPv6 ? client.MapToIPv4() : client;
        foreach (var network in Networks)
        {
            if (network.Contains(address))
                return true;
        }

        return false;
    }

    public string CanonicalKey()
    {
        if (Networks.Length == 0)
            return string.Empty;

        return string.Join('|', Networks
            .Select(static n => n.ToString())
            .OrderBy(static s => s, StringComparer.OrdinalIgnoreCase));
    }

    public static bool TryParse(
        string[]? clients,
        [NotNullWhen(true)] out ClientAccessList? list,
        [NotNullWhen(false)] out string? error)
    {
        list = Unrestricted;
        error = null;
        if (clients is null || clients.Length == 0)
            return true;

        var networks = new IPNetwork[clients.Length];
        for (var i = 0; i < clients.Length; i++)
        {
            var raw = clients[i];
            if (string.IsNullOrWhiteSpace(raw))
            {
                error = $"[{i}] is empty";
                list = null;
                return false;
            }

            if (TryParseClientNetwork(raw, out networks[i]))
                continue;

            error = $"[{i}] is not a CIDR or IP: {raw}";
            list = null;
            return false;
        }

        list = new ClientAccessList(networks);
        return true;
    }

    public static bool TryParseClientNetwork(string input, out IPNetwork network)
    {
        var trimmed = input.Trim();
        if (IPNetwork.TryParse(trimmed, out network))
            return true;

        if (IPAddress.TryParse(trimmed, out var host))
        {
            var prefix = host.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            network = new IPNetwork(host, prefix);
            return true;
        }

        network = default;
        return false;
    }
}
