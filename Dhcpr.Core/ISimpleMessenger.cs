namespace Dhcpr.Core;

public interface ISimpleMessenger
{
    IDisposable Subscribe(ISubscriber subscriber);
    ValueTask BroadcastAsync(object sender, object data, CancellationToken cancellationToken);
    ValueTask SendTo(object receiver, object sender, object data, CancellationToken cancellationToken);
}