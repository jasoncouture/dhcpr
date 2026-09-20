using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.DependencyInjection;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class CompositeDomainMessageMiddlewareTests
{
    [Fact]
    public async Task WalksLeavesByPriorityAndReturnsFirstNonNull()
    {
        var request = DomainMessage.CreateRequest("example.com");
        var lateAnswer = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var early = Leaf(priority: 200, result: lateAnswer);
        var pass = Leaf(priority: 50, result: null);
        var unused = Leaf(priority: 500, result: DomainMessage.CreateResponse(
            request,
            responseCode: DomainResponseCode.ServerFailure));

        var composite = new CompositeDomainMessageMiddleware(early, pass, unused);
        var context = new DomainMessageContext(null, null, request);

        var result = await composite.ProcessAsync(context, CancellationToken.None);

        Assert.Same(lateAnswer, result);
        Assert.Equal("leaf-200", context.AnsweredBy);
        await unused.DidNotReceive()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LeavesExistingAnsweredByAlone()
    {
        var request = DomainMessage.CreateRequest("example.com");
        var answer = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var leaf = Leaf(priority: 1, result: answer);
        var context = new DomainMessageContext(null, null, request) { AnsweredBy = "Cache" };

        await new CompositeDomainMessageMiddleware(leaf).ProcessAsync(context, CancellationToken.None);

        Assert.Equal("Cache", context.AnsweredBy);
    }

    [Fact]
    public async Task StopsWhenContextCancelIsSet()
    {
        var request = DomainMessage.CreateRequest("example.com");
        var first = Substitute.For<IDomainMessageMiddleware>();
        first.Priority.Returns(1);
        first.Name.Returns("cancel");
        first.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                call.Arg<DomainMessageContext>().Cancel = true;
                return (DomainMessage?)null;
            });
        var second = Leaf(priority: 2, result: DomainMessage.CreateResponse(
            request,
            responseCode: DomainResponseCode.NoError));

        var result = await new CompositeDomainMessageMiddleware(first, second)
            .ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.Null(result);
        await second.DidNotReceive()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public void AddDnsRegistersSingleMiddlewarePipeline()
    {
        var services = new ServiceCollection();
        services.AddDns();

        var middleware = services
            .Where(static d => d.ServiceType == typeof(IDomainMessageMiddleware) && !d.IsKeyedService)
            .ToList();

        Assert.Single(middleware);
        Assert.Contains(services, static d => d.ServiceType == typeof(ServerFailureDomainMiddleware));
    }

    private static IDomainMessageMiddleware Leaf(int priority, DomainMessage? result)
    {
        var leaf = Substitute.For<IDomainMessageMiddleware>();
        leaf.Priority.Returns(priority);
        leaf.Name.Returns($"leaf-{priority}");
        leaf.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(result);
        return leaf;
    }
}
