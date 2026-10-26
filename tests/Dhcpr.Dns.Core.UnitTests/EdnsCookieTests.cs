using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.UnitTests;

public class EdnsCookieTests
{
    [Fact]
    public void StripCookiesRemovesCookieOption()
    {
        var records = new DomainResourceRecords(
            ImmutableArray<DomainResourceRecord>.Empty,
            ImmutableArray<DomainResourceRecord>.Empty,
            ImmutableArray.Create(OptWithCookie(ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8))));

        var stripped = EdnsCookie.StripCookies(records);
        Assert.DoesNotContain(
            ((OptionData)stripped.Additional[0].Data).Options,
            o => o.Code == EdnsCookie.OptionCode);
    }

    private static DomainResourceRecord OptWithCookie(ImmutableArray<byte> cookie)
        => new(
            DomainLabels.Empty,
            DomainRecordType.OPT,
            (DomainRecordClass)1232,
            TimeSpan.Zero,
            new OptionData(ImmutableArray.Create(new EdnsOption(EdnsCookie.OptionCode, cookie))));
}
