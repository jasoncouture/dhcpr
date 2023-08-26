using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

namespace Dhcpr.Dns.Core;

public sealed class InternalResolver : IRequestResolver
{
    public void Remove(string domain, RecordType recordType, bool removeSubDomains = false, bool removeRecords = true)
    {
        var container = _rootContainer.Lookup(domain, (int)recordType);
        if (container is null) return;
        if (removeSubDomains)
            container?.ClearSubdomains();
        if (removeRecords)
            container?.ClearSubdomains();

        _rootContainer.CollectGarbage(domain, (int)recordType);
    }

    private RootDnsRecordContainer _rootContainer = new RootDnsRecordContainer();

    public Task<IResponse> Resolve(IRequest request, CancellationToken cancellationToken = new CancellationToken())
    {
        var response = Response.FromRequest(request);

        foreach (var question in request.Questions)
        {
            var results = AnswerQuestion(question);

            if (results is null) continue;

            foreach (var answer in results)
            {
                response.AnswerRecords.Add(answer);
            }
        }

        return Task.FromResult((IResponse)response);
    }

    private IEnumerable<IResourceRecord>? AnswerQuestion(Question question)
    {
        var result = _rootContainer.Lookup(question.Name.ToString()!, (int)question.Type);
        return result?.GetRecords();
    }
}