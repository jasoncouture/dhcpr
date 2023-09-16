﻿using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Data.Dns.Models;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class RecursiveRootResolver : IDomainMessageMiddleware
{
    private readonly IDomainClientFactory _clientFactory;
    private readonly ObjectPool<StringBuilder> _stringBuilderPool;
    private readonly ILogger<RecursiveRootResolver> _logger;
    private readonly ImmutableArray<IPEndPoint> _servers;

    public RecursiveRootResolver(
        IEnumerable<IPEndPoint> servers,
        IDomainClientFactory clientFactory,
        ObjectPool<StringBuilder> stringBuilderPool,
        ILogger<RecursiveRootResolver> logger
    )
    {
        _servers = servers.ToImmutableArray();
        _clientFactory = clientFactory;
        _stringBuilderPool = stringBuilderPool;
        _logger = logger;
    }

    private static readonly DomainRecordType[] NameServerRecordTypes = { DomainRecordType.A, DomainRecordType.AAAA };


    public async ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var question = context.DomainMessage.Questions[0];
        using var labels = question.Name.Labels.ToPooledList();
        using var endPoints = _servers.ToPooledList();
        var builder = _stringBuilderPool.Get();
        using var addressRecords = ListPool<IPAddress>.Default.Get();
        try
        {
            while (labels.Count > 1)
            {
                addressRecords.Clear();
                var next = labels[^1];
                labels.RemoveAt(labels.Count - 1);
                if (builder.Length > 0)
                    builder.Insert(0, '.');
                builder.Insert(0, next);

                var resolver = await _clientFactory.GetParallelDomainClient(
                    endPoints.Select(i => new DomainClientOptions() { EndPoint = i, Type = DomainClientType.Udp }),
                    cancellationToken);
                var message = DomainMessage.CreateRequest(builder.ToString(), DomainRecordType.NS);

                var responseMessage = await resolver.SendAsync(message, cancellationToken);
                addressRecords.AddRange(responseMessage.Records
                    .Where(i => i.Type is DomainRecordType.A or DomainRecordType.AAAA)
                    .Select(i => (IPAddressData)i.RecordData)
                    .Select(i => i.Address));
                if (addressRecords.Count != 0)
                {
                    endPoints.Clear();
                    endPoints.AddRange(addressRecords.Select(i => new IPEndPoint(i, 53)));
                    continue;
                }

                var internalClient =
                    await _clientFactory.GetDomainClient(new DomainClientOptions() { Type = DomainClientType.Internal },
                        cancellationToken);
                using var nameserverQueries = GetNameserverNames(responseMessage.Records.Where(i =>
                        i.Type == DomainRecordType.NS || i.Type == DomainRecordType.SOA)).Select(i =>
                        internalClient.SendAsync(DomainMessage.CreateRequest(i), cancellationToken).AsTask()
                            .OperationCancelledToNull()
                            .ConvertExceptionsToNull()
                    )
                    .ToPooledList();
                addressRecords.Clear();

                var results = await Task.WhenAll(nameserverQueries);

                addressRecords.AddRange(
                    results.Where(i => i is not null)
                        .SelectMany(i => i!.Records)
                        .Where(i => i.Type is DomainRecordType.A or DomainRecordType.AAAA)
                        .Select(i => (IPAddressData)i.RecordData)
                        .Select(i => i.Address)
                );

                if (addressRecords.Count == 0) return null;

                endPoints.Clear();
                endPoints.AddRange(addressRecords.Select(i => new IPEndPoint(i, 53)));
            }

            var finalResolver = await _clientFactory.GetParallelDomainClient(
                endPoints.Select(i => new DomainClientOptions() { EndPoint = i, Type = DomainClientType.Udp }),
                cancellationToken);
            var clonedRequest = context.DomainMessage with { Id = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1) };
            return await finalResolver.SendAsync(clonedRequest, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An unhandled exception occurred while resolving recursively.");
            return null;
        }
        finally
        {
            _stringBuilderPool.Return(builder);
        }
    }

    private IEnumerable<string> GetNameserverNames(IEnumerable<DomainResourceRecord> records)
    {
        foreach (var record in records)
        {
            switch (record.Type)
            {
                case DomainRecordType.NS:
                    yield return ((NameData)record.RecordData).Name.ToString();
                    break;
                case DomainRecordType.SOA:
                    yield return record.Name.ToString();
                    break;
            }
        }
    }

    public string Name { get; } = "Recursive Resolver";
    public int Priority { get; } = 5000;
}