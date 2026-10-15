using Dhcpr.Core.Queue;

namespace Dhcpr.Core.UnitTests;

public class QueueProcessorServiceTests
{
    [Fact]
    public async Task RemoveCompletedTasksUsesLiveListIndex()
    {
        var pending = new TaskCompletionSource();
        var running = pending.Task;
        var tasks = new List<Task> { Task.CompletedTask, running, Task.CompletedTask };

        await QueueProcessorService<object>.RemoveCompletedTasksAsync(tasks, CancellationToken.None);

        var remaining = Assert.Single(tasks);
        Assert.Same(running, remaining);
        pending.SetResult();
        await remaining;
    }
}
