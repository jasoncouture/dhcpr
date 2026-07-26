using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class AnswerShuffleMiddlewareTests
{
    [Fact]
    public async Task SingleAddressResponseIsUnchanged()
    {
        var request = DomainMessage.CreateRequest("example.com");
        var response = DomainMessage.CreateResponse(
            request,
            new[] { A("example.com", "1.1.1.1") },
            responseCode: DomainResponseCode.NoError);

        var result = await RunAsync(response, request);

        Assert.Same(response, result);
    }

    [Fact]
    public async Task PreservesCnamePrefixAndAddressMultiset()
    {
        var request = DomainMessage.CreateRequest("www.example.com");
        var response = DomainMessage.CreateResponse(
            request,
            new[]
            {
                Cname("www.example.com", "example.com"),
                A("example.com", "1.1.1.1"),
                A("example.com", "2.2.2.2"),
                A("example.com", "3.3.3.3"),
            },
            responseCode: DomainResponseCode.NoError);

        var seenDifferentOrder = false;
        for (var attempt = 0; attempt < 40; attempt++)
        {
            var shuffled = await RunAsync(response, request);
            Assert.NotNull(shuffled);
            Assert.Equal(DomainRecordType.CNAME, shuffled!.Records.Answers[0].Type);
            Assert.Equal(
                response.Records.Answers.Where(r => r.Type == DomainRecordType.A).Select(Address).OrderBy(a => a),
                shuffled.Records.Answers.Where(r => r.Type == DomainRecordType.A).Select(Address).OrderBy(a => a));

            var originalAddresses = response.Records.Answers.Where(r => r.Type == DomainRecordType.A).Select(Address);
            var shuffledAddresses = shuffled.Records.Answers.Where(r => r.Type == DomainRecordType.A).Select(Address);
            if (!originalAddresses.SequenceEqual(shuffledAddresses))
            {
                seenDifferentOrder = true;
                break;
            }
        }

        Assert.True(seenDifferentOrder);
    }

    private static async Task<DomainMessage?> RunAsync(DomainMessage response, DomainMessage request)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage?>(response));

        var middleware = new AnswerShuffleMiddleware(inner);
        return await middleware.ProcessAsync(
            new DomainMessageContext(null, null, request),
            CancellationToken.None);
    }

    private static DomainResourceRecord A(string owner, string ip)
        => new(
            new DomainLabels(owner),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(60),
            new IPAddressData(IPAddress.Parse(ip)));

    private static DomainResourceRecord Cname(string owner, string target)
        => new(
            new DomainLabels(owner),
            DomainRecordType.CNAME,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(60),
            new NameData(new DomainLabels(target)));

    private static string Address(DomainResourceRecord record)
        => ((IPAddressData)record.Data).Address.ToString();
}
