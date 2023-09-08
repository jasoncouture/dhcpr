using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System;

namespace Dhcpr.Peering.Discovery;

public class StaticConfiguration
{
    public Uri[] Peers { get; set; } = Array.Empty<Uri>();
}