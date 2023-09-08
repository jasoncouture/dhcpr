namespace Dhcpr.Data;

public class DatabaseExpirationTracker : IDatabaseExpirationTracker
{
    private static readonly TimeSpan ScanInterval = TimeSpan.FromMinutes(2);
    private DateTimeOffset _lastProcessingTime = DateTimeOffset.Now.Subtract(ScanInterval);

    public bool ShouldScanForExpirations(DateTimeOffset currentTimeStamp)
    {
        return (currentTimeStamp - _lastProcessingTime) > ScanInterval;
    }

    public void ScanForExpirationComplete(DateTimeOffset currentTimeStamp)
    {
        _lastProcessingTime = currentTimeStamp;
    }
}