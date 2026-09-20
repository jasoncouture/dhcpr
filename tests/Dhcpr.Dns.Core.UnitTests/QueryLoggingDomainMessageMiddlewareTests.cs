using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class QueryLoggingDomainMessageMiddlewareTests
{
    [Fact]
    public async Task PassesThroughResponseFromInner()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            new[]
            {
                new DomainResourceRecord(
                    new DomainLabels("example.com"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new IPAddressData(IPAddress.Parse("93.184.216.34")))
            },
            responseCode: DomainResponseCode.NoError);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));

        var middleware = new QueryLoggingDomainMessageMiddleware(
            inner,
            NullLogger<QueryLoggingDomainMessageMiddleware>.Instance);

        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
        await inner.Received(1).ProcessAsync(context, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task DoesNotLogInternalRequests()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));

        var logger = CreateLogger();
        var middleware = new QueryLoggingDomainMessageMiddleware(inner, logger);

        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            IsInternal = true
        };

        await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Equal(0, CountLogs(logger, LogLevel.Information));
        await inner.Received(1).ProcessAsync(context, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task LogsExternalRequests()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));

        var logger = CreateLogger();
        var middleware = new QueryLoggingDomainMessageMiddleware(inner, logger);

        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Equal(1, CountLogs(logger, LogLevel.Information));
    }

    [Fact]
    public async Task LogsServFailAsErrorWithReason()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.ANY);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.ServerFailure);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                call.Arg<DomainMessageContext>().ServFailReason = "unsupported query type 255";
                return new ValueTask<DomainMessage>(response);
            });

        var logger = CreateLogger();
        var middleware = new QueryLoggingDomainMessageMiddleware(inner, logger);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Equal(0, CountLogs(logger, LogLevel.Information));
        Assert.Equal(1, CountLogs(logger, LogLevel.Error));
    }

    private static ILogger<QueryLoggingDomainMessageMiddleware> CreateLogger()
    {
        var logger = Substitute.For<ILogger<QueryLoggingDomainMessageMiddleware>>();
        logger.IsEnabled(Arg.Any<LogLevel>()).Returns(true);
        return logger;
    }

    private static int CountLogs(ILogger logger, LogLevel level) =>
        logger.ReceivedCalls().Count(call =>
            call.GetMethodInfo().Name == nameof(ILogger.Log) &&
            Equals(call.GetArguments()[0], level));
}
