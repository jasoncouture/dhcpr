using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public class NoCacheResponse : IResponse
{
    private readonly IResponse _responseImplementation;

    public NoCacheResponse(IResponse responseImplementation)
    {
        _responseImplementation = responseImplementation;
    }

    public byte[] ToArray()
    {
        return _responseImplementation.ToArray();
    }

    public IList<Question> Questions => _responseImplementation.Questions;

    public int Size => _responseImplementation.Size;

    public int Id
    {
        get => _responseImplementation.Id;
        set => _responseImplementation.Id = value;
    }

    public IList<IResourceRecord> AnswerRecords => _responseImplementation.AnswerRecords;

    public IList<IResourceRecord> AuthorityRecords => _responseImplementation.AuthorityRecords;

    public IList<IResourceRecord> AdditionalRecords => _responseImplementation.AdditionalRecords;

    public bool RecursionAvailable
    {
        get => _responseImplementation.RecursionAvailable;
        set => _responseImplementation.RecursionAvailable = value;
    }

    public bool AuthenticData
    {
        get => _responseImplementation.AuthenticData;
        set => _responseImplementation.AuthenticData = value;
    }

    public bool CheckingDisabled
    {
        get => _responseImplementation.CheckingDisabled;
        set => _responseImplementation.CheckingDisabled = value;
    }

    public bool AuthorativeServer
    {
        get => _responseImplementation.AuthorativeServer;
        set => _responseImplementation.AuthorativeServer = value;
    }

    public bool Truncated
    {
        get => _responseImplementation.Truncated;
        set => _responseImplementation.Truncated = value;
    }

    public OperationCode OperationCode
    {
        get => _responseImplementation.OperationCode;
        set => _responseImplementation.OperationCode = value;
    }

    public ResponseCode ResponseCode
    {
        get => _responseImplementation.ResponseCode;
        set => _responseImplementation.ResponseCode = value;
    }
}