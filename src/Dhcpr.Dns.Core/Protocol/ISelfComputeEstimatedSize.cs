namespace Dhcpr.Dns.Core.Protocol;

public interface ISelfComputeEstimatedSize
{
    /// <summary>
    /// Wire size in bytes, used to pre-size encode buffers.
    /// </summary>
    int EstimatedSize { get; }
}