using System.Diagnostics.CodeAnalysis;
using System.Net;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

public sealed class TlsConfiguration : IValidateSelf
{
    public const int DefaultPort = 853;

    public const int DefaultHttpsPort = 443;

    public bool Enabled { get; set; }

    public string[] Listeners { get; set; } = [];

    public int HttpsPort { get; set; } = DefaultHttpsPort;

    public string CertificatePath { get; set; } = "";

    public string PrivateKeyPath { get; set; } = "";

    private EndPoint[] _parsedListeners = [];

    public IReadOnlyList<EndPoint> GetParsedListeners() => _parsedListeners;

    public bool Validate() => TryValidate(out _);

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by configuration binding")]
    public bool TryValidate([NotNullWhen(false)] out string? error)
    {
        Listeners ??= [];
        CertificatePath ??= "";
        PrivateKeyPath ??= "";

        if (!Enabled)
        {
            _parsedListeners = [];
            error = null;
            return true;
        }

        if (Listeners.Length == 0)
        {
            error = "TLS:Listeners must contain at least one listen address when TLS is enabled";
            return false;
        }

        var parsed = new EndPoint[Listeners.Length];
        for (var i = 0; i < Listeners.Length; i++)
        {
            if (string.IsNullOrWhiteSpace(Listeners[i]) ||
                !Listeners[i].TryGetEndPoint(DefaultPort, out var endPoint))
            {
                error = $"TLS:Listeners[{i}] is not a valid IP or hostname: {Listeners[i]}";
                return false;
            }

            parsed[i] = endPoint;
        }

        if (string.IsNullOrWhiteSpace(CertificatePath))
        {
            error = "TLS:CertificatePath is required when TLS is enabled";
            return false;
        }

        if (string.IsNullOrWhiteSpace(PrivateKeyPath))
        {
            error = "TLS:PrivateKeyPath is required when TLS is enabled";
            return false;
        }

        if (HttpsPort is < 1 or > ushort.MaxValue)
        {
            error = "TLS:HttpsPort must be 1–65535 when TLS is enabled";
            return false;
        }

        _parsedListeners = parsed;
        error = null;
        return true;
    }
}
