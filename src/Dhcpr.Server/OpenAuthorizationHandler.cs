using Microsoft.AspNetCore.Authorization;

namespace Dhcpr.Server;

/// <summary>
/// Satisfies every authorization requirement so the operator UI is open
/// when OpenID Connect is disabled.
/// </summary>
public sealed class OpenAuthorizationHandler : IAuthorizationHandler
{
    public Task HandleAsync(AuthorizationHandlerContext context)
    {
        foreach (var requirement in context.PendingRequirements.ToArray())
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}
