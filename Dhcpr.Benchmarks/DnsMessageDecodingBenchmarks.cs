﻿using System.Diagnostics.CodeAnalysis;

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
        Payload = new byte[]
        {
            183, 6, 129, 0, 0, 1, 0, 0, 0, 13, 0, 15, 3, 99, 111, 109, 0, 0, 2, 0, 1, 192, 12, 0, 2, 0, 1, 0, 2,
            163, 0, 0, 20, 1, 102, 12, 103, 116, 108, 100, 45, 115, 101, 114, 118, 101, 114, 115, 3, 110, 101, 116,
            0, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 97, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1,
            108, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 100, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163,
            0, 0, 4, 1, 105, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 98, 192, 35, 192, 12, 0, 2, 0, 1,
            0, 2, 163, 0, 0, 4, 1, 103, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 99, 192, 35, 192, 12,
            0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 101, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 106, 192,
            35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 104, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4,
            1, 107, 192, 35, 192, 12, 0, 2, 0, 1, 0, 2, 163, 0, 0, 4, 1, 109, 192, 35, 192, 241, 0, 1, 0, 1, 0, 2,
            163, 0, 0, 4, 192, 55, 83, 30, 192, 81, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 41, 162, 30, 192, 225, 0,
            1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 52, 178, 30, 192, 193, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 48, 79,
            30, 192, 113, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 43, 172, 30, 192, 209, 0, 1, 0, 1, 0, 2, 163, 0, 0,
            4, 192, 54, 112, 30, 192, 145, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 42, 93, 30, 192, 33, 0, 1, 0, 1, 0,
            2, 163, 0, 0, 4, 192, 35, 51, 30, 192, 177, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 12, 94, 30, 192, 97, 0,
            1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 31, 80, 30, 192, 161, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 26, 92, 30,
            192, 129, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192, 33, 14, 30, 192, 65, 0, 1, 0, 1, 0, 2, 163, 0, 0, 4, 192,
            5, 6, 30, 192, 241, 0, 28, 0, 1, 0, 2, 163, 0, 0, 16, 32, 1, 5, 1, 177, 249, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            48, 192, 81, 0, 28, 0, 1, 0, 2, 163, 0, 0, 16, 32, 1, 5, 0, 217, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48,
        };
    }

    private static byte[] Payload { get; }

    [Benchmark]
    public void Library()
    {
        for (var x = 0; x < 1024; x++)
        {
            Response.FromArray(Payload);
        }
    }

    [Benchmark]
    public void DomainMessage()
    {
        for (var x = 0; x < 1024; x++)
        {
            DomainMessageEncoder.Decode(Payload);
        }
    }
}