using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.Authoritative;

public sealed class AuthoritativeZone
{
    public AuthoritativeZone(
        string apex,
        DomainResourceRecord soaRecord,
        ImmutableLabelTreeNode nameTree,
        string sourcePath)
    {
        Apex = RootZoneSnapshot.NormalizeOwner(apex);
        SoaRecord = soaRecord;
        NameTree = nameTree;
        SourcePath = sourcePath;
        ApexLabels = Apex.Length == 0
            ? ImmutableArray<string>.Empty
            : Apex.Split('.').ToImmutableArray();
    }

    public string Apex { get; }
    public ImmutableArray<string> ApexLabels { get; }
    public DomainResourceRecord SoaRecord { get; }
    public ImmutableLabelTreeNode NameTree { get; }
    public string SourcePath { get; }

    public StartOfAuthorityData Soa => (StartOfAuthorityData)SoaRecord.Data;
}
