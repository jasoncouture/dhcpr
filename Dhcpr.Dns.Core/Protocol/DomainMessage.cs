using System.Collections.Immutable;

using Dhcpr.Core.Linq;

namespace Dhcpr.Dns.Core.Protocol;

public record DomainMessage(ushort Id, DomainMessageFlags Flags, ImmutableArray<DomainQuestion> Questions,
    DomainResourceRecords Records) : ISelfComputeEstimatedSize
{
    private int? _size;

    // The additional 4 ushorts are the counts for questions and answers.
    public int EstimatedSize => _size ??= Flags.EstimatedSize + Records.EstimatedSize + Questions.Select(i => i.EstimatedSize).DefaultIfEmpty(0).Sum() +
                                 (sizeof(ushort) * 5); // Fields: Id, Counts:Questions, Answers, Authority, Additional)

    public static DomainMessage CreateRequest(string domain, DomainRecordType type = DomainRecordType.A,
        DomainRecordClass @class = DomainRecordClass.IN, bool recursionRequested = true,
        DomainOperationCode requestType = DomainOperationCode.Query)
    {
        return new DomainMessage((ushort)Random.Shared.Next(0, (int)ushort.MaxValue + 1),
            new DomainMessageFlags(
                false,
                requestType,
                false,
                false,
                recursionRequested,
                false,
                false,
                false,
                DomainResponseCode.NoError
            ),
            new[] { new DomainQuestion(new DomainLabels(domain), type, @class) }.ToImmutableArray(),
            DomainResourceRecords.Empty);
    }
    public static DomainMessage CreateResponse(
        DomainMessage request,
        IEnumerable<DomainResourceRecord>? answers = null,
        IEnumerable<DomainResourceRecord>? authorities = null,
        IEnumerable<DomainResourceRecord>? additional = null,
        DomainResponseCode responseCode = DomainResponseCode.NameError
    )
    {

        answers ??= Enumerable.Empty<DomainResourceRecord>();
        authorities ??= Enumerable.Empty<DomainResourceRecord>();
        additional ??= Enumerable.Empty<DomainResourceRecord>();
        using var answerRecordsPooledList = answers.ToPooledList();
        using var authorityRecordsPooledList = authorities.ToPooledList();
        using var additionalRecordsPooledList = additional.ToPooledList();
        var records = DomainResourceRecords.Empty;
        if (answerRecordsPooledList.Count + authorityRecordsPooledList.Count + additionalRecordsPooledList.Count > 0)
        {
            records = new DomainResourceRecords(answerRecordsPooledList.ToImmutableArray(),
                authorityRecordsPooledList.ToImmutableArray(), additionalRecordsPooledList.ToImmutableArray());
        }

        return CreateResponse(request, records, responseCode);
    }
    public static DomainMessage CreateResponse(
        DomainMessage request,
        DomainResourceRecords resourceRecords,
        DomainResponseCode responseCode = DomainResponseCode.NameError

    )
    {
        return new DomainMessage(
            request.Id,
            request.Flags with { Response = true, ResponseCode = responseCode },
            request.Questions,
            resourceRecords
        );
    }
}