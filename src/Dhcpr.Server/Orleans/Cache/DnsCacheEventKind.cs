namespace Dhcpr.Server.Orleans.Cache;

public enum DnsCacheEventKind : byte
{
    Set = 0,
    UpdateSecurityStatus = 1,
    Clear = 2
}
