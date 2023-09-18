using System.Diagnostics.CodeAnalysis;

using BenchmarkDotNet.Attributes;

using Dhcpr.Dns.Core.Protocol.Parser;

using DNS.Protocol;

namespace Dhcpr.Benchmarks;

[MemoryDiagnoser]
[SuppressMessage("ReSharper", "ClassCanBeSealed.Global")]
public class DnsMessageDecodingBenchmarks
{
    static DnsMessageDecodingBenchmarks()
    {
        Payload = DnsMessageEncodingBenchmarks.Request.ToArray();
    }
    private static byte[] Payload { get; }

    [Benchmark]
    public void Library()
    {
        Request.FromArray(Payload);
    }

    [Benchmark]
    public void DomainMessage()
    {
        DomainMessageEncoder.Decode(Payload);
    }
}