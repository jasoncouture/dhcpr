namespace Dhcpr.Data;

internal interface IDatabaseExpirationTracker
{
    bool ShouldScanForExpirations(DateTimeOffset currentTimeStamp);
    void ScanForExpirationComplete(DateTimeOffset currentTimeStamp);
}