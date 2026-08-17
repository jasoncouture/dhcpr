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

        Assert.Single(tasks);
        Assert.Same(running, tasks[0]);
        pending.SetResult();
        await running;
    }
}
