using System.Diagnostics.CodeAnalysis;

using BenchmarkDotNet.Attributes;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;

using DNS.Protocol;


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

[MemoryDiagnoser]
[SuppressMessage("ReSharper", "ClassCanBeSealed.Global")]
public class DnsMessageEncodingBenchmarks
{
    static DnsMessageEncodingBenchmarks()
    {
        Request = new Request { Id = 1234, RecursionDesired = true };
        Request.Questions.Add(new Question(new Domain("www.google.com")));

        DomainMessage = DomainMessageEncoder.Decode(Request.ToArray());
    }

    public static Request Request { get; }
    public static DomainMessage DomainMessage { get; }

    [Benchmark]
    public void DnsLibraryEncode()
    {
        Request.ToArray();
    }

    [Benchmark]
    public void DomainMessageEncode()
    {
        Span<byte> buffer = stackalloc byte[DomainMessage.EstimatedSize];
        DomainMessageEncoder.Encode(buffer, DomainMessage);
    }
}