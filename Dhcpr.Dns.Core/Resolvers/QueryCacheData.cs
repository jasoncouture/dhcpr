﻿using DNS.Protocol;

namespace Dhcpr.Dns.Core;

public record class QueryCacheData(byte[] Payload, DateTimeOffset Created)
{
    public QueryCacheData(IResponse response) : this(response.ToArray(), DateTimeOffset.Now) { }
}