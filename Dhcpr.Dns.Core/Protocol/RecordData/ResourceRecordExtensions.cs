using System.Diagnostics.CodeAnalysis;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public static class ResourceRecordExtensions
{
    [SuppressMessage("ReSharper", "SwitchStatementHandlesSomeKnownEnumValuesWithDefault")]
    public static IDomainResourceRecordData ToData(this ReadOnlySpan<byte> bytes, DomainRecordType type)
    {
        var parsingSpan = new ReadOnlyDnsParsingSpan(bytes);
        switch (type)
        {
            case DomainRecordType.A:
            case DomainRecordType.AAAA:
                return CreateData<IPAddressData>(parsingSpan);
            case DomainRecordType.NS:
            case DomainRecordType.CNAME:
            case DomainRecordType.PTR:
                return CreateData<NameData>(parsingSpan);
            case DomainRecordType.SOA:
                return CreateData<StartOfAuthorityData>(parsingSpan);
            case DomainRecordType.MX:
                return CreateData<MailExchangerData>(parsingSpan);
            case DomainRecordType.TXT:
                return CreateData<TextData>(parsingSpan);
            case DomainRecordType.SRV:
                return CreateData<ServiceData>(parsingSpan);
            default:
                return CreateData<BlobData>(parsingSpan);
        }
    }

    private static IDomainResourceRecordData CreateData<T>(ReadOnlyDnsParsingSpan bytes)
        where T : IDomainResourceRecordData
        => T.ReadFrom(bytes);
}