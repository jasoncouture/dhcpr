using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class ReferralWalkerGlueTests
{
    [Fact]
    public async Task AlwaysResolvesMaxGlueNamesWhenAvailable()
    {
        var queries = new List<string>();
        var walker = new ReferralWalker(Client(queries, _ =>
            [IPAddress.Parse("192.0.2.1"), IPAddress.Parse("2001:db8::1")]));

        var names = Enumerable.Range(0, 9).Select(i => $"{(char)('a' + i)}.ntpns.org").ToArray();
        var addresses = await walker.ResolveNameserverAddressesAsync(
            Context(),
            names,
            CancellationToken.None);

        Assert.Equal(ReferralWalker.MaxGlueNamesPerCut * 2, addresses.Count);
        Assert.Equal(ReferralWalker.MaxGlueNamesPerCut * 2, queries.Count);
        Assert.Equal(
            ReferralWalker.MaxGlueNamesPerCut,
            queries.Select(q => q.Split('/')[0]).Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public async Task TriesASecondNameWhenTheFirstReturnsNothing()
    {
        var queries = new List<string>();
        var walker = new ReferralWalker(Client(queries, name =>
            name.Equals("b.ntpns.org", StringComparison.OrdinalIgnoreCase)
                ? [IPAddress.Parse("192.0.2.2")]
                : []));

        var addresses = await walker.ResolveNameserverAddressesAsync(
            Context(),
            ["a.ntpns.org", "b.ntpns.org"],
            CancellationToken.None);

        Assert.Contains(IPAddress.Parse("192.0.2.2"), addresses);
        Assert.True(queries.Count <= ReferralWalker.MaxGlueNamesPerCut * 2);
    }

    [Fact]
    public async Task DoesNotQueryMoreThanMaxGlueNames()
    {
        var queries = new List<string>();
        var walker = new ReferralWalker(Client(queries, _ => []));

        var names = Enumerable.Range(0, 9).Select(i => $"{(char)('a' + i)}.ntpns.org").ToArray();
        var addresses = await walker.ResolveNameserverAddressesAsync(
            Context(),
            names,
            CancellationToken.None);

        Assert.Empty(addresses);
        Assert.Equal(ReferralWalker.MaxGlueNamesPerCut * 2, queries.Count);
    }

    private static DomainMessageContext Context()
        => new(null, null, DomainMessage.CreateRequest("example.com"));

    private static IInternalDomainClient Client(
        List<string> queries,
        Func<string, IReadOnlyList<IPAddress>> addressesFor)
    {
        var client = Substitute.For<IInternalDomainClient>();
        client.SendAsync(
                Arg.Any<DomainMessageContext>(),
                Arg.Any<DomainMessage>(),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var request = call.Arg<DomainMessage>();
                var question = request.Questions[0];
                var name = question.Name.ToString();
                queries.Add($"{name}/{question.Type}");
                var records = addressesFor(name)
                    .Where(ip =>
                        question.Type == DomainRecordType.A && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ||
                        question.Type == DomainRecordType.AAAA && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    .Select(ip => new DomainResourceRecord(
                        question.Name,
                        question.Type,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(60),
                        new IPAddressData(ip)))
                    .ToArray();
                return new ValueTask<DomainMessage>(
                    DomainMessage.CreateResponse(request, records, responseCode: DomainResponseCode.NoError));
            });
        return client;
    }
}
