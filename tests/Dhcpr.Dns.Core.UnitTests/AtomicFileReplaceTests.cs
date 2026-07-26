using Dhcpr.Dns.Core.RootZone;

namespace Dhcpr.Dns.Core.UnitTests;

public class AtomicFileReplaceTests
{
    [Fact]
    public async Task WriteAsync_ReplacesDestinationViaTempFile()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dhcpr-atomic-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(dir);
        var dest = Path.Combine(dir, "root.zone");
        try
        {
            await AtomicFileReplace.WriteAsync(dest, "first\n", CancellationToken.None);
            Assert.Equal("first\n", await File.ReadAllTextAsync(dest));

            await AtomicFileReplace.WriteAsync(dest, "second\n", CancellationToken.None);
            Assert.Equal("second\n", await File.ReadAllTextAsync(dest));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }
}
