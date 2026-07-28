using DnsZone.IO;

namespace Dhcpr.Dns.Core.Authoritative;

/// <summary>
/// DnsZone <see cref="IDnsSource"/> that loads a start file and resolves <c>$INCLUDE</c>
/// relative to the including file's directory. Applies the BIND unsupported-RR filter
/// to every loaded blob.
/// </summary>
public sealed class BindFileDnsSource : IDnsSource
{
    private readonly string _startPath;
    private readonly Func<string, string> _filter;

    public BindFileDnsSource(string startPath, Func<string, string> filter)
    {
        _startPath = Path.GetFullPath(startPath);
        _filter = filter;
    }

    public string LoadContent(string? fileName)
    {
        var path = string.IsNullOrWhiteSpace(fileName) ? _startPath : fileName;
        var text = File.ReadAllText(path);
        return _filter(text);
    }

    public string ResolveFile(string fileName, string? referrer)
    {
        var baseDir = Path.GetDirectoryName(string.IsNullOrWhiteSpace(referrer) ? _startPath : referrer)
                      ?? Path.GetDirectoryName(_startPath)
                      ?? ".";
        var combined = Path.GetFullPath(Path.Combine(baseDir, fileName));
        return File.Exists(combined) ? combined : null!;
    }
}
