using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

namespace Dhcpr.Dns.Core.UnitTests;

public class CanonicalNameResolverDecoratorTests
{
    [Fact]
    public async Task ChasedAddressesArePlacedInAnswers()
    {
        var cnameTarget = "star-mini.c10r.facebook.com";
        var address = IPAddress.Parse("157.240.3.35");

        var inner = new StubMiddleware(request =>
        {
            return DomainMessage.CreateResponse(
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
                responseCode: DomainResponseCode.NoError);
        });

        var factory = new FixedInternalClientFactory(request =>
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

        var decorator = new CanonicalNameResolverDecorator(inner, factory);
        var request = DomainMessage.CreateRequest("www.facebook.com", DomainRecordType.A);
        var result = await decorator.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r => r.Type == DomainRecordType.CNAME);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.A && ((IPAddressData)r.Data).Address.Equals(address));
        Assert.Empty(result.Records.Additional);
    }

    [Fact]
    public async Task NestedCnameChainIsPreservedInAnswers()
    {
        var factory = new FixedInternalClientFactory(request =>
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

        var inner = new StubMiddleware(request => DomainMessage.CreateResponse(
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

        var decorator = new CanonicalNameResolverDecorator(inner, factory);
        var request = DomainMessage.CreateRequest("www.example", DomainRecordType.A);
        var result = await decorator.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(3, result!.Records.Answers.Length);
        Assert.Equal(DomainRecordType.CNAME, result.Records.Answers[0].Type);
        Assert.Equal(DomainRecordType.CNAME, result.Records.Answers[1].Type);
        Assert.Equal(DomainRecordType.A, result.Records.Answers[2].Type);
    }

    private sealed class StubMiddleware : IDomainMessageMiddleware
    {
        private readonly Func<DomainMessage, DomainMessage> _handler;

        public StubMiddleware(Func<DomainMessage, DomainMessage> handler) => _handler = handler;

        public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult<DomainMessage?>(_handler(context.DomainMessage));

        public string Name => "stub";
        public int Priority => 0;
    }

    private sealed class FixedInternalClientFactory : IDomainClientFactory
    {
        private readonly Func<DomainMessage, DomainMessage> _handler;

        public FixedInternalClientFactory(Func<DomainMessage, DomainMessage> handler) => _handler = handler;

        public ValueTask<IDomainClient> GetParallelDomainClient(IEnumerable<DomainClientOptions> options,
            CancellationToken cancellationToken = default)
            => throw new NotSupportedException();

        public ValueTask<IDomainClient> GetDomainClient(DomainClientOptions options,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult<IDomainClient>(new DelegateClient(_handler));

        private sealed class DelegateClient : IDomainClient
        {
            private readonly Func<DomainMessage, DomainMessage> _handler;
            public DelegateClient(Func<DomainMessage, DomainMessage> handler) => _handler = handler;

            public ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
                => ValueTask.FromResult(_handler(message));
        }
    }
}
