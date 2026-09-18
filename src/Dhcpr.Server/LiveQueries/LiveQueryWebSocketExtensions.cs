using Microsoft.Extensions.Logging;

namespace Dhcpr.Server.LiveQueries;

public static class LiveQueryWebSocketExtensions
{
    public const string Path = "/ws/queries";

    public static WebApplication MapLiveQueryWebSocket(this WebApplication app)
    {
        app.MapGet(Path, HandleAsync)
            .RequireAuthorization(OidcAuthenticationExtensions.DnsViewerPolicy);
        return app;
    }

    private static async Task HandleAsync(
        HttpContext httpContext,
        IGrainFactory grainFactory,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        if (!httpContext.WebSockets.IsWebSocketRequest)
        {
            httpContext.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        using var socket = await httpContext.WebSockets.AcceptWebSocketAsync();
        await LiveQueryWebSocketSession.RunAsync(
            socket,
            grainFactory,
            loggerFactory.CreateLogger(typeof(LiveQueryWebSocketSession).FullName!),
            cancellationToken);
    }
}
