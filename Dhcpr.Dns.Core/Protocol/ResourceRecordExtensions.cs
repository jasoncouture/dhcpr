namespace Dhcpr.Dns.Core.Protocol;

public static class ResourceRecordExtensions
{
    public static IDomainResourceRecordData ToData(this ReadOnlySpan<byte> bytes, DomainRecordType type)
    {
        switch (type)
        {
            case DomainRecordType.A:
            case DomainRecordType.AAAA:
                return CreateData<IPAddressData>(bytes);
            case DomainRecordType.NS:
            case DomainRecordType.CNAME:
            case DomainRecordType.PTR:
                return CreateData<NameData>(bytes);
            case DomainRecordType.SOA:
                return CreateData<StartOfAuthorityData>(bytes);
            case DomainRecordType.MX:
                return CreateData<MailExchangerData>(bytes);
            case DomainRecordType.TXT:
                return CreateData<TextData>(bytes);
            case DomainRecordType.SRV:
                return CreateData<ServiceData>(bytes);
            default:
                return CreateData<BlobData>(bytes);
        }
    }

    private static IDomainResourceRecordData CreateData<T>(ReadOnlySpan<byte> bytes) where T : IDomainResourceRecordData 
        => T.ReadFrom(bytes);
}