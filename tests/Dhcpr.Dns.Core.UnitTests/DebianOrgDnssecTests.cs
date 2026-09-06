using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;
using Dhcpr.Dns.Core.Validation;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DebianOrgDnssecTests
{
    private static readonly DateTimeOffset FrozenNow = new(2026, 9, 6, 14, 0, 0, TimeSpan.Zero);

    [Fact]
    public void DebianOrgDnsKeyRrsetVerifies()
    {
        var keys = Answers("debian.org.DNSKEY", DomainRecordType.DNSKEY);
        var rrsigs = Covering("debian.org.DNSKEY", "debian.org", DomainRecordType.DNSKEY);
        var crypto = Crypto();
        var ksks = keys.Where(k => ((DomainNameSystemKeyData)k.Data).Flags == 257).ToList();

        Assert.True(
            DnssecRrsetVerifier.TryVerifyRrset(crypto, keys, rrsigs, ksks, FrozenNow),
            $"DNSKEY RRset did not verify. {DescribeKeys(crypto, keys)}");
    }

    [Fact]
    public void DebianOrgARrsetVerifies()
    {
        var keys = Answers("debian.org.DNSKEY", DomainRecordType.DNSKEY);
        var records = Answers("debian.org.A", DomainRecordType.A);
        var rrsigs = Covering("debian.org.A", "debian.org", DomainRecordType.A);
        var crypto = Crypto();

        Assert.True(
            DnssecRrsetVerifier.TryVerifyRrset(crypto, records, rrsigs, keys, FrozenNow),
            $"A RRset did not verify. {DescribeKeys(crypto, keys)}");
    }

    [Fact]
    public void DebianOrgNsRrsetVerifies()
    {
        var keys = Answers("debian.org.DNSKEY", DomainRecordType.DNSKEY);
        var records = Answers("debian.org.NS", DomainRecordType.NS);
        var rrsigs = Covering("debian.org.NS", "debian.org", DomainRecordType.NS);
        var crypto = Crypto();

        Assert.True(
            DnssecRrsetVerifier.TryVerifyRrset(crypto, records, rrsigs, keys, FrozenNow),
            $"NS RRset did not verify. {DescribeKeys(crypto, keys)}");
    }

    [Fact]
    public void DebianOrgDsMatchesKsk()
    {
        var keys = Answers("debian.org.DNSKEY", DomainRecordType.DNSKEY);
        var dsRecords = Answers("debian.org.DS", DomainRecordType.DS);
        var crypto = Crypto();
        var matched = keys.Count(key =>
            dsRecords.Any(ds => crypto.VerifyDelegationSigner((DelegationSignerData)ds.Data, key)));

        Assert.True(matched > 0, $"No DNSKEY matched DS. {DescribeKeys(crypto, keys)}");
    }

    [Fact]
    public void OrgNsRrsetVerifies()
    {
        var keys = Answers("org.DNSKEY", DomainRecordType.DNSKEY);
        var records = Answers("org.NS", DomainRecordType.NS);
        var rrsigs = Covering("org.NS", "org", DomainRecordType.NS);
        var crypto = Crypto();

        Assert.True(
            DnssecRrsetVerifier.TryVerifyRrset(crypto, records, rrsigs, keys, FrozenNow),
            $"org NS did not verify. {DescribeKeys(crypto, keys)}");
    }

    [Fact]
    public void OrgSoaRrsetVerifies()
    {
        var keys = Answers("org.DNSKEY", DomainRecordType.DNSKEY);
        var records = Answers("org.SOA", DomainRecordType.SOA);
        var rrsigs = Covering("org.SOA", "org", DomainRecordType.SOA);
        var crypto = Crypto();

        Assert.True(
            DnssecRrsetVerifier.TryVerifyRrset(crypto, records, rrsigs, keys, FrozenNow),
            $"org SOA did not verify. {DescribeKeys(crypto, keys)}");
    }

    [Fact]
    public async Task DebianOrgA_WithCompleteKeyMaterial_IsSecure()
    {
        var request = DomainMessage.CreateRequest("debian.org");
        var response = Load("debian.org.A");
        response = response with { Id = request.Id, Questions = request.Questions };

        var middleware = CreateMiddleware(response, ScriptedChain());
        var scope = new DnssecScope();
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, request) { DnssecScope = scope },
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DnssecValidationStatus.Secure, scope.Status);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.True(result.Flags.Authentic);
    }

    [Fact]
    public async Task DebDebianOrgAssembled_SignedCnameUnsignedA_IsInsecureNotBogus()
    {
        var cnameMessage = Load("deb.debian.org.CNAME");
        var cname = cnameMessage.Records.Answers.Where(r => r.Type is DomainRecordType.CNAME).ToList();
        var cnameSigs = DnssecRrsetVerifier.FindCoveringRrsigs(
            cnameMessage.Records.Answers, new DomainLabels("deb.debian.org"), DomainRecordType.CNAME);
        var fastlyA = new DomainResourceRecord(
            new DomainLabels("debian.map.fastlydns.net"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(60),
            new IPAddressData(System.Net.IPAddress.Parse("199.232.134.132")));

        var request = DomainMessage.CreateRequest("deb.debian.org");
        var response = DomainMessage.CreateResponse(
            request,
            answers: cname.Concat(cnameSigs).Append(fastlyA),
            responseCode: DomainResponseCode.NoError);

        var middleware = CreateMiddleware(response, ScriptedChain());
        var scope = new DnssecScope();
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, request) { DnssecScope = scope },
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.NotEqual(DnssecValidationStatus.Bogus, scope.Status);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.False(result.Flags.Authentic);
        Assert.Equal(DnssecValidationStatus.Insecure, scope.Status);
    }

    private static IInternalDomainClient ScriptedChain()
    {
        return ScriptedInternalClient(request =>
        {
            var q = request.Questions[0];
            var name = q.Name.ToString();
            if (q.Type is DomainRecordType.DNSKEY && name.Length == 0)
                return Load("root.DNSKEY") with { Id = request.Id, Questions = request.Questions };
            if (q.Type is DomainRecordType.DNSKEY && name.Equals("org", StringComparison.OrdinalIgnoreCase))
                return Load("org.DNSKEY") with { Id = request.Id, Questions = request.Questions };
            if (q.Type is DomainRecordType.DNSKEY && name.Equals("debian.org", StringComparison.OrdinalIgnoreCase))
                return Load("debian.org.DNSKEY") with { Id = request.Id, Questions = request.Questions };
            if (q.Type is DomainRecordType.DS && name.Equals("org", StringComparison.OrdinalIgnoreCase))
                return Load("org.DS") with { Id = request.Id, Questions = request.Questions };
            if (q.Type is DomainRecordType.DS && name.Equals("debian.org", StringComparison.OrdinalIgnoreCase))
                return Load("debian.org.DS") with { Id = request.Id, Questions = request.Questions };
            return DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure);
        });
    }

    private static DnssecValidationMiddleware CreateMiddleware(
        DomainMessage response,
        IInternalDomainClient internalClient)
    {
        var options = Monitor(new DnsConfiguration());
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance, options);
        var validator = new DnssecMessageValidator(
            crypto, internalClient, options, NullLogger<DnssecMessageValidator>.Instance);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(response);
        return new DnssecValidationMiddleware(
            inner,
            validator,
            new DnsResponseCache(new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 })),
            options,
            NullLogger<DnssecValidationMiddleware>.Instance);
    }

    private static IInternalDomainClient ScriptedInternalClient(Func<DomainMessage, DomainMessage> handler)
    {
        var client = Substitute.For<IInternalDomainClient>();
        client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(ci => new ValueTask<DomainMessage>(handler(ci.Arg<DomainMessage>())));
        client.SendAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(ci => new ValueTask<DomainMessage>(handler(ci.ArgAt<DomainMessage>(1))));
        client.SendAsync(
                Arg.Any<DomainMessageContext>(),
                Arg.Any<DomainMessage>(),
                Arg.Any<ImmutableArray<System.Net.IPEndPoint>>(),
                Arg.Any<CancellationToken>())
            .Returns(ci => new ValueTask<DomainMessage>(handler(ci.ArgAt<DomainMessage>(1))));
        return client;
    }

    private static List<DomainResourceRecord> Answers(string fixture, DomainRecordType type)
        => Load(fixture).Records.Answers.Where(r => r.Type == type).ToList();

    private static List<DomainResourceRecord> Covering(string fixture, string owner, DomainRecordType type)
        => DnssecRrsetVerifier.FindCoveringRrsigs(Load(fixture).Records.Answers, new DomainLabels(owner), type).ToList();

    private static DomainMessage Load(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Fixtures", "dnssec", name + ".hex");
        var hex = File.ReadAllText(path).Trim();
        return DomainMessageEncoder.Decode(Convert.FromHexString(hex));
    }

    private static DnssecValidator Crypto()
        => new(NullLogger<DnssecValidator>.Instance, Monitor(new DnsConfiguration()));

    private static IOptionsMonitor<DnsConfiguration> Monitor(DnsConfiguration value)
    {
        var monitor = Substitute.For<IOptionsMonitor<DnsConfiguration>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }

    private static string DescribeKeys(IDnssecValidator crypto, IEnumerable<DomainResourceRecord> keys)
        => string.Join("; ", keys.Select(k =>
        {
            var data = (DomainNameSystemKeyData)k.Data;
            return $"alg={data.Algorithm} flags={data.Flags} tag={crypto.CalculateKeyTag(data, k)}";
        }));
}
