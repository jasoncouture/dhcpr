using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class CanonicalNameResolverDecoratorTests
{
    [Fact]
    public async Task ChasedAddressesArePlacedInAnswers()
    {
        var cnameTarget = "star-mini.c10r.facebook.com";
        var address = IPAddress.Parse("157.240.3.35");

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                var request = callInfo.ArgAt<DomainMessageContext>(0).DomainMessage;
                return new ValueTask<DomainMessage?>(DomainMessage.CreateResponse(
                    request,
                    new[]
                    {
                        new DomainResourceRecord(
                            new DomainLabels("www.facebook.com"),
                            DomainRecordType.CNAME,
                            DomainRecordClass.IN,
                            TimeSpan.FromSeconds(60),
                            new NameData(new DomainLabels(cnameTarget)))
                    },
                    responseCode: DomainResponseCode.NoError));
            });

        var internalClient = CreateInternalClient(request =>
        {
            Assert.Equal(cnameTarget, request.Questions[0].Name.ToString());
            Assert.Equal(DomainRecordType.A, request.Questions[0].Type);
            return DomainMessage.CreateResponse(
                request,
                new[]
                {
                    new DomainResourceRecord(
                        new DomainLabels(cnameTarget),
                        DomainRecordType.A,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(60),
                        new IPAddressData(address))
                },
                responseCode: DomainResponseCode.NoError);
        });

        var decorator = new CanonicalNameResolverDecorator(inner, internalClient);
        var request = DomainMessage.CreateRequest("www.facebook.com", DomainRecordType.A);
        var result = await decorator.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r => r.Type == DomainRecordType.CNAME);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.A && ((IPAddressData)r.Data).Address.Equals(address));
        Assert.Empty(result.Records.Additional);
    }

    [Fact]
    public async Task BundledAddressesWithCnameAreIgnoredAndTargetIsLookedUp()
    {
        var cnameTarget = "example.com";
        var staleAddress = IPAddress.Parse("1.2.3.4");
        var freshAddress = IPAddress.Parse("9.9.9.9");

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                var request = callInfo.ArgAt<DomainMessageContext>(0).DomainMessage;
                return new ValueTask<DomainMessage?>(DomainMessage.CreateResponse(
                    request,
                    new[]
                    {
                        new DomainResourceRecord(
                            new DomainLabels("www.example.com"),
                            DomainRecordType.CNAME,
                            DomainRecordClass.IN,
                            TimeSpan.FromSeconds(60),
                            new NameData(new DomainLabels(cnameTarget))),
                        new DomainResourceRecord(
                            new DomainLabels(cnameTarget),
                            DomainRecordType.A,
                            DomainRecordClass.IN,
                            TimeSpan.FromSeconds(60),
                            new IPAddressData(staleAddress))
                    },
                    responseCode: DomainResponseCode.NoError));
            });

        var internalClient = CreateInternalClient(request =>
        {
            Assert.Equal(cnameTarget, request.Questions[0].Name.ToString());
            Assert.Equal(DomainRecordType.A, request.Questions[0].Type);
            return DomainMessage.CreateResponse(
                request,
                new[]
                {
                    new DomainResourceRecord(
                        new DomainLabels(cnameTarget),
                        DomainRecordType.A,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(60),
                        new IPAddressData(freshAddress))
                },
                responseCode: DomainResponseCode.NoError);
        });

        var decorator = new CanonicalNameResolverDecorator(inner, internalClient);
        var request = DomainMessage.CreateRequest("www.example.com", DomainRecordType.A);
        var result = await decorator.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r => r.Type == DomainRecordType.CNAME);
        Assert.DoesNotContain(result.Records.Answers, r =>
            r.Type == DomainRecordType.A && ((IPAddressData)r.Data).Address.Equals(staleAddress));
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.A && ((IPAddressData)r.Data).Address.Equals(freshAddress));
    }

    [Fact]
    public async Task NestedCnameChainIsPreservedInAnswers()
    {
        var internalClient = CreateInternalClient(request =>
        {
            var name = request.Questions[0].Name.ToString();
            if (name.Equals("alias1.example", StringComparison.OrdinalIgnoreCase))
            {
                return DomainMessage.CreateResponse(
                    request,
                    new[]
                    {
                        new DomainResourceRecord(
                            new DomainLabels("alias1.example"),
                            DomainRecordType.CNAME,
                            DomainRecordClass.IN,
                            TimeSpan.FromSeconds(60),
                            new NameData(new DomainLabels("alias2.example"))),
                        new DomainResourceRecord(
                            new DomainLabels("alias2.example"),
                            DomainRecordType.A,
                            DomainRecordClass.IN,
                            TimeSpan.FromSeconds(60),
                            new IPAddressData(IPAddress.Parse("10.0.0.1")))
                    },
                    responseCode: DomainResponseCode.NoError);
            }

            return DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.NameError);
        });

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                var request = callInfo.ArgAt<DomainMessageContext>(0).DomainMessage;
                return new ValueTask<DomainMessage?>(DomainMessage.CreateResponse(
                    request,
                    new[]
                    {
                        new DomainResourceRecord(
                            new DomainLabels("www.example"),
                            DomainRecordType.CNAME,
                            DomainRecordClass.IN,
                            TimeSpan.FromSeconds(60),
                            new NameData(new DomainLabels("alias1.example")))
                    },
                    responseCode: DomainResponseCode.NoError));
            });

        var decorator = new CanonicalNameResolverDecorator(inner, internalClient);
        var request = DomainMessage.CreateRequest("www.example", DomainRecordType.A);
        var result = await decorator.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(3, result!.Records.Answers.Length);
        Assert.Equal(DomainRecordType.CNAME, result.Records.Answers[0].Type);
        Assert.Equal(DomainRecordType.CNAME, result.Records.Answers[1].Type);
        Assert.Equal(DomainRecordType.A, result.Records.Answers[2].Type);
    }

    private static IInternalDomainClient CreateInternalClient(Func<DomainMessage, DomainMessage> handler)
    {
        var client = Substitute.For<IInternalDomainClient>();
        client.SendAsync(
                Arg.Any<DomainMessageContext>(),
                Arg.Any<DomainMessage>(),
                Arg.Any<CancellationToken>())
            .Returns(callInfo => new ValueTask<DomainMessage>(handler(callInfo.ArgAt<DomainMessage>(1))));
        client.SendAsync(
                Arg.Any<DomainMessageContext>(),
                Arg.Any<DomainMessage>(),
                Arg.Any<ImmutableArray<IPEndPoint>>(),
                Arg.Any<CancellationToken>())
            .Returns(callInfo => new ValueTask<DomainMessage>(handler(callInfo.ArgAt<DomainMessage>(1))));
        client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(callInfo => new ValueTask<DomainMessage>(handler(callInfo.ArgAt<DomainMessage>(0))));
        return client;
    }
}
