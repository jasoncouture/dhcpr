namespace Dhcpr.Core;

public interface ISubscriber
{
    ValueTask OnMessageAsync(object sender, object data, CancellationToken cancellationToken);
}