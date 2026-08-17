namespace Dhcpr.Core;

public interface ISubscriber
{
    /// <summary>
    /// Handles a message delivered by <see cref="ISimpleMessenger"/>.
    /// </summary>
    /// <param name="sender">The publisher of the message.</param>
    /// <param name="data">The message payload.</param>
    /// <param name="cancellationToken">Token used to cancel delivery.</param>
    ValueTask OnMessageAsync(object sender, object data, CancellationToken cancellationToken);
}