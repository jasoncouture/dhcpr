// See https://aka.ms/new-console-template for more information

using Dhcpr.Dns.Core;

Console.WriteLine("Loading root hints...");
await RootHints.RefreshAsync(CancellationToken.None);
var hints = (await RootHints.GetRootServers(CancellationToken.None)).ToPooledList();

Console.WriteLine($"Got {hints.Count} hint(s)");
foreach (var hint in hints)
{
    Console.WriteLine(hint);
}