using System.Collections.Immutable;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class AnswerShuffleMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;

    public AnswerShuffleMiddleware(IDomainMessageMiddleware inner)
    {
        _inner = inner;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var result = await _inner.ProcessAsync(context, cancellationToken);
        return result is null ? null : ShuffleAddressAnswers(result);
    }

    private static DomainMessage ShuffleAddressAnswers(DomainMessage message)
    {
        var answers = message.Records.Answers;
        if (answers.Length <= 1)
            return message;

        var addressIndices = new List<int>();
        for (var i = 0; i < answers.Length; i++)
        {
            if (answers[i].Type is DomainRecordType.A or DomainRecordType.AAAA)
                addressIndices.Add(i);
        }

        if (addressIndices.Count <= 1)
            return message;

        var shuffled = answers.ToArray();
        for (var i = addressIndices.Count - 1; i > 0; i--)
        {
            var j = Random.Shared.Next(i + 1);
            var left = addressIndices[i];
            var right = addressIndices[j];
            (shuffled[left], shuffled[right]) = (shuffled[right], shuffled[left]);
        }

        return message with
        {
            Records = message.Records with { Answers = shuffled.ToImmutableArray() }
        };
    }
}
