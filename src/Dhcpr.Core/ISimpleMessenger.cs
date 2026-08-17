namespace Dhcpr.Core;

public interface ISimpleMessenger
{
    /// <summary>
    /// Registers <paramref name="subscriber"/> to receive broadcasts and targeted sends.
    /// </summary>
    /// <returns>A disposable that unsubscribes when disposed.</returns>
    IDisposable Subscribe(ISubscriber subscriber);

    /// <summary>
    /// Delivers <paramref name="data"/> to every live subscriber.
    /// </summary>
    ValueTask BroadcastAsync(object sender, object data, CancellationToken cancellationToken);

    /// <summary>
    /// Delivers <paramref name="data"/> to <paramref name="receiver"/> when that object is a subscribed <see cref="ISubscriber"/>.
    /// </summary>
    ValueTask SendToAsync(object receiver, object sender, object data, CancellationToken cancellationToken);
}