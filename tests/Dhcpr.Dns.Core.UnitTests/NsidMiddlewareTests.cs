using System.Collections.Immutable;
using System.Text;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class NsidMiddlewareTests
{
    private const ushort OptionCode = 3;

    [Fact]
    public async Task LeavesTheResponseAloneWhenNsidWasNotRequested()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var inner = InnerReturning(response);
        var middleware = new NsidMiddleware(inner);

        var result = await middleware.ProcessAsync(Context(request), CancellationToken.None);

        Assert.Same(response, result);
    }

    [Fact]
    public async Task AddsMachineNameWhenQueryIncludesEmptyNsid()
    {
        var request = WithNsid(DomainMessage.CreateRequest("example.com", DomainRecordType.A), ImmutableArray<byte>.Empty);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var middleware = new NsidMiddleware(InnerReturning(response));

        var result = await middleware.ProcessAsync(Context(request), CancellationToken.None);

        var nsid = Assert.Single(NsidOptions(result));
        Assert.Equal(MachineNameBytes(), nsid.Data.ToArray());
    }

    [Fact]
    public async Task ReplacesQueryPayloadAndKeepsOtherOptions()
    {
        var request = WithNsid(
            DomainMessage.CreateRequest("example.com", DomainRecordType.A),
            ImmutableArray.Create<byte>(1, 2, 3));
        var ede = EdnsExtendedError.Create(EdnsExtendedError.DnssecBogus);
        var response = DomainMessage.CreateResponse(
            request,
            additional: [ede],
            responseCode: DomainResponseCode.ServerFailure);
        var middleware = new NsidMiddleware(InnerReturning(response));

        var result = await middleware.ProcessAsync(Context(request), CancellationToken.None);

        var options = OptOptions(result);
        Assert.Contains(options, static o => o.Code == EdnsExtendedError.OptionCode);
        var nsid = Assert.Single(options, static o => o.Code == OptionCode);
        Assert.Equal(MachineNameBytes(), nsid.Data.ToArray());
    }

    [Fact]
    public async Task SkipsInternalHops()
    {
        var request = WithNsid(DomainMessage.CreateRequest("example.com", DomainRecordType.A), ImmutableArray<byte>.Empty);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var middleware = new NsidMiddleware(InnerReturning(response));
        var context = Context(request) with { IsInternal = true };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
    }

    private static IDomainMessageMiddleware InnerReturning(DomainMessage response)
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(response);
        return inner;
    }

    private static DomainMessageContext Context(DomainMessage request)
        => new(null, null, request);

    private static byte[] MachineNameBytes()
        => Encoding.UTF8.GetBytes(Environment.MachineName.ToLower());

    private static DomainMessage WithNsid(DomainMessage message, ImmutableArray<byte> payload)
    {
        var opt = new DomainResourceRecord(
            DomainLabels.Empty,
            DomainRecordType.OPT,
            (DomainRecordClass)1232,
            TimeSpan.Zero,
            new OptionData(ImmutableArray.Create(new EdnsOption(OptionCode, payload))));
        return message with
        {
            Records = message.Records with { Additional = message.Records.Additional.Add(opt) }
        };
    }

    private static ImmutableArray<EdnsOption> OptOptions(DomainMessage message)
    {
        foreach (var record in message.Records.Additional)
        {
            if (record.Type is DomainRecordType.OPT && record.Data is OptionData data)
                return data.Options;
        }

        return ImmutableArray<EdnsOption>.Empty;
    }

    private static IEnumerable<EdnsOption> NsidOptions(DomainMessage message)
        => OptOptions(message).Where(static o => o.Code == OptionCode);
}
