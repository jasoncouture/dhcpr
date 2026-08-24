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
            case DomainRecordType.DNAME:
            case DomainRecordType.ALIAS:
            case DomainRecordType.MD:
            case DomainRecordType.MF:
            case DomainRecordType.MB:
            case DomainRecordType.MG:
            case DomainRecordType.MR:
                return CreateData<NameData>(ref parsingSpan, dataLength);
            case DomainRecordType.SOA:
                return CreateData<StartOfAuthorityData>(ref parsingSpan, dataLength);
            case DomainRecordType.MX:
                return CreateData<MailExchangerData>(ref parsingSpan, dataLength);
            case DomainRecordType.TXT:
                return CreateData<TextData>(ref parsingSpan, dataLength);
            case DomainRecordType.HINFO:
                return CreateData<HostInformationData>(ref parsingSpan, dataLength);
            case DomainRecordType.SRV:
                return CreateData<ServiceData>(ref parsingSpan, dataLength);
            case DomainRecordType.NAPTR:
                return CreateData<NamingAuthorityPointerData>(ref parsingSpan, dataLength);
            case DomainRecordType.OPT:
                return CreateData<OptionData>(ref parsingSpan, dataLength);
            case DomainRecordType.DNSKEY:
                return CreateData<DomainNameSystemKeyData>(ref parsingSpan, dataLength);
            case DomainRecordType.DS:
                return CreateData<DelegationSignerData>(ref parsingSpan, dataLength);
            case DomainRecordType.SSHFP:
                return CreateData<SshFingerprintData>(ref parsingSpan, dataLength);
            case DomainRecordType.RRSIG:
                return CreateData<ResourceRecordSignatureData>(ref parsingSpan, dataLength);
            case DomainRecordType.NSEC:
                return CreateData<NextSecureData>(ref parsingSpan, dataLength);
            case DomainRecordType.NSEC3:
                return CreateData<NextSecure3Data>(ref parsingSpan, dataLength);
            case DomainRecordType.NSEC3PARAM:
                return CreateData<NextSecure3ParameterData>(ref parsingSpan, dataLength);
            case DomainRecordType.TLSA:
                return CreateData<TlsAssociationData>(ref parsingSpan, dataLength);
            case DomainRecordType.CAA:
                return CreateData<CertificationAuthorityAuthorizationData>(ref parsingSpan, dataLength);
            case DomainRecordType.LUA:
                return CreateData<LuaRecordData>(ref parsingSpan, dataLength);
            case DomainRecordType.SVCB:
            case DomainRecordType.HTTPS:
                return CreateData<SvcbData>(ref parsingSpan, dataLength);
            default:
                return CreateData<BlobData>(ref parsingSpan, dataLength);
        }
    }

    private static IDomainResourceRecordData CreateData<T>(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
        where T : IDomainResourceRecordData
        => T.ReadFrom(ref bytes, dataLength);
}