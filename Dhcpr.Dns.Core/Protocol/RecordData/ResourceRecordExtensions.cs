using System.Diagnostics.CodeAnalysis;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public static class ResourceRecordExtensions
{
    [SuppressMessage("ReSharper", "SwitchStatementHandlesSomeKnownEnumValuesWithDefault")]
    public static IDomainResourceRecordData ToData(this ref ReadOnlyDnsParsingSpan parsingSpan, DomainRecordType type, int dataLength)
    {
        switch (type)
        {
            case DomainRecordType.A:
            case DomainRecordType.AAAA:
                return CreateData<IPAddressData>(ref parsingSpan, dataLength);
            case DomainRecordType.NS:
            case DomainRecordType.CNAME:
            case DomainRecordType.PTR:
                return CreateData<NameData>(ref parsingSpan, dataLength);
            case DomainRecordType.SOA:
                return CreateData<StartOfAuthorityData>(ref parsingSpan, dataLength);
            case DomainRecordType.MX:
                return CreateData<MailExchangerData>(ref parsingSpan, dataLength);
            case DomainRecordType.TXT:
                return CreateData<TextData>(ref parsingSpan, dataLength);
            case DomainRecordType.SRV:
                return CreateData<ServiceData>(ref parsingSpan, dataLength);
            default:
                return CreateData<BlobData>(ref parsingSpan, dataLength);
        }
    }

    private static IDomainResourceRecordData CreateData<T>(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
        where T : IDomainResourceRecordData
        => T.ReadFrom(ref bytes, dataLength);
}