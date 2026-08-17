namespace Dhcpr.Dns.Core.Authoritative;

public enum ZoneAnswerKind
{
    NoMatch,
    Answer,
    NoData,
    NameError,
    Referral
}
