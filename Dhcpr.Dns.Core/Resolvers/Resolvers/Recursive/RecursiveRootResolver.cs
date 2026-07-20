using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class RecursiveRootResolver : IDomainMessageMiddleware
{
    private readonly IDomainClientFactory _clientFactory;
    private readonly ObjectPool<StringBuilder> _stringBuilderPool;
    private readonly ILogger<RecursiveRootResolver> _logger;
    private readonly ImmutableArray<IPEndPoint> _servers;

    public RecursiveRootResolver(
        IOptionsMonitor<RootServerConfiguration> rootServerConfiguration,
        IDomainClientFactory clientFactory,
        ObjectPool<StringBuilder> stringBuilderPool,
        ILogger<RecursiveRootResolver> logger
    )
    {
        _servers = rootServerConfiguration.CurrentValue.Addresses
            .Select(i => i.GetEndPoint(53))
            .Cast<IPEndPoint>()
            .Shuffle()
            .ToImmutableArray();
        _clientFactory = clientFactory;
        _stringBuilderPool = stringBuilderPool;
        _logger = logger;
    }

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
            while (labels.Count > 0)
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
                using var nsNames = GetNameserverNames(responseMessage.Records).ToPooledList();

                // Authoritative NODATA / no referral — keep current nameservers and continue.
                if (nsNames.Count == 0)
                    continue;

                var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
                addressRecords.AddRange(GetGlueAddresses(responseMessage.Records, nsNameSet));

                if (addressRecords.Count == 0)
                {
                    var internalClient =
                        await _clientFactory.GetDomainClient(
                            new DomainClientOptions() { Type = DomainClientType.Internal },
                            cancellationToken);

                    using var nameserverQueries = nsNames
                        .SelectMany([SuppressMessage("ReSharper", "AccessToDisposedClosure")] (name) =>
                            new[]
                            {
                                internalClient
                                    .SendAsync(DomainMessage.CreateRequest(name, DomainRecordType.A),
                                        cancellationToken).AsTask(),
                                internalClient
                                    .SendAsync(DomainMessage.CreateRequest(name, DomainRecordType.AAAA),
                                        cancellationToken).AsTask()
                            })
                        .Select(i => i.OperationCancelledToNull().ConvertExceptionsToNull())
                        .ToPooledList();

                    var responses = await Task.WhenAll(nameserverQueries);
                    foreach (var nextMessage in responses)
                    {
                        if (nextMessage is null) continue;
                        addressRecords.AddRange(nextMessage.Records
                            .Where(i => i.Type is DomainRecordType.A or DomainRecordType.AAAA)
                            .Select(i => ((IPAddressData)i.Data).Address));
                    }
                }

                // Could not resolve NS addresses — keep current endpoints.
                if (addressRecords.Count == 0)
                    continue;

                endPoints.Clear();
                endPoints.AddRange(addressRecords.Select(i => new IPEndPoint(i, 53)));
            }

            var finalResolver = await _clientFactory.GetParallelDomainClient(
                endPoints.Select(i => new DomainClientOptions() { EndPoint = i, Type = DomainClientType.Udp }),
                cancellationToken);
            var clonedRequest = context.DomainMessage with { Id = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1) };
            var result = await finalResolver.SendAsync(clonedRequest, cancellationToken);

            if (result.Records.Answers.Length != 0 ||
                clonedRequest.Questions[0].Type is not (DomainRecordType.A or DomainRecordType.AAAA))
            {
                return result;
            }

            clonedRequest = clonedRequest with
            {
                Questions = clonedRequest.Questions.Select(x => x with { Type = DomainRecordType.CNAME })
                    .ToImmutableArray()
            };
            var cnameResponse = await finalResolver.SendAsync(clonedRequest, cancellationToken);
            if (cnameResponse.Records.Answers.Length > 0 &&
                cnameResponse.Flags.ResponseCode is DomainResponseCode.NoError)
            {
                return cnameResponse;
            }

            return result;
        }
        catch (Exception ex)
        {
            if(!cancellationToken.IsCancellationRequested) {
                _logger.LogError(ex, "An unhandled exception occurred while resolving recursively.");
            }
            
            return DomainMessage.CreateResponse(context.DomainMessage, DomainResourceRecords.Empty,
                DomainResponseCode.ServerFailure);
        }
        finally
        {
            _stringBuilderPool.Return(builder);
        }
    }

    private static IEnumerable<string> GetNameserverNames(IEnumerable<DomainResourceRecord> records)
    {
        foreach (var record in records)
        {
            if (record.Type is not DomainRecordType.NS)
                continue;
            if (record.Data is not NameData nameData)
                continue;
            yield return nameData.Name.ToString();
        }
    }

    private static IEnumerable<IPAddress> GetGlueAddresses(
        IEnumerable<DomainResourceRecord> records,
        HashSet<string> nsNames)
    {
        foreach (var record in records)
        {
            if (record.Type is not (DomainRecordType.A or DomainRecordType.AAAA))
                continue;
            if (!nsNames.Contains(record.Name.ToString()))
                continue;
            if (record.Data is not IPAddressData addressData)
                continue;
            yield return addressData.Address;
        }
    }

    public string Name { get; } = "Recursive Resolver";
    public int Priority { get; } = 5000;
}
