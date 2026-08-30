using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;

namespace Dhcpr.Server.UnitTests;

public class OpenAuthorizationHandlerTests
{
    [Fact]
    public async Task SucceedsEveryPendingRequirement()
    {
        var handler = new OpenAuthorizationHandler();
        var user = new System.Security.Claims.ClaimsPrincipal();
        var context = new AuthorizationHandlerContext(
            [new DenyAnonymousAuthorizationRequirement(), new RolesAuthorizationRequirement(["dns-admin"])],
            user,
            resource: null);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
        Assert.False(context.HasFailed);
        Assert.Empty(context.PendingRequirements);
    }
}
