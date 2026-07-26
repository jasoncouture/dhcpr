using System.Net;
using System.Net.Http.Headers;

using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;

namespace Dhcpr.Server;

public static class DnsOverHttpEndpointExtensions
{
    public const string DnsQueryPath = "/dns-query";
    public const string DnsMessageMediaType = "application/dns-message";

    // nginx-style "client closed request"; not defined on ASP.NET StatusCodes.
    private const int ClientClosedRequest = 499;

    public static WebApplication MapDnsOverHttp(this WebApplication app)
    {
        app.MapPost(DnsQueryPath, HandlePostAsync);
        app.MapGet(DnsQueryPath, HandleGetAsync);
        return app;
    }

    private static async Task<IResult> HandlePostAsync(
        HttpContext httpContext,
        IDnsQueryExecutor executor,
        IOptions<DnsConfiguration> dnsOptions,
        CancellationToken cancellationToken)
    {
        if (!IsDnsMessageContentType(httpContext.Request.ContentType))
            return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);

        var maxBytes = dnsOptions.Value.DnsOverHttp.MaxRequestBytes;
        if (httpContext.Request.ContentLength is > 0 and var contentLength && contentLength > maxBytes)
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);

        ReadOnlyMemory<byte> wire;
        try
        {
            wire = await ReadBodyAsync(httpContext.Request.Body, maxBytes, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (PayloadTooLargeException)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }

        return await ExecuteAsync(httpContext, executor, wire, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IResult> HandleGetAsync(
        HttpContext httpContext,
        IDnsQueryExecutor executor,
        IOptions<DnsConfiguration> dnsOptions,
        CancellationToken cancellationToken)
    {
        if (!httpContext.Request.Query.TryGetValue("dns", out var dnsValues) ||
            string.IsNullOrEmpty(dnsValues))
        {
            return Results.BadRequest();
        }

        byte[] wire;
        try
        {
            wire = Base64UrlTextEncoder.Decode(dnsValues.ToString());
        }
        catch (FormatException)
        {
            return Results.BadRequest();
        }

        if (wire.Length > dnsOptions.Value.DnsOverHttp.MaxRequestBytes)
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);

        return await ExecuteAsync(httpContext, executor, wire, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IResult> ExecuteAsync(
        HttpContext httpContext,
        IDnsQueryExecutor executor,
        ReadOnlyMemory<byte> wire,
        CancellationToken cancellationToken)
    {
        var client = GetClientEndPoint(httpContext);
        var server = GetServerEndPoint(httpContext);
        var result = await executor.ExecuteAsync(wire, client, server, cancellationToken)
            .ConfigureAwait(false);

        return result.Status switch
        {
            DnsQueryExecutionStatus.Success => Results.Bytes(
                result.ResponseWire!,
                DnsMessageMediaType),
            DnsQueryExecutionStatus.EmptyRequest => Results.BadRequest(),
            DnsQueryExecutionStatus.RequestTooLarge => Results.StatusCode(StatusCodes.Status413PayloadTooLarge),
            DnsQueryExecutionStatus.InvalidWireFormat => Results.BadRequest(),
            DnsQueryExecutionStatus.NoResponse => Results.StatusCode(StatusCodes.Status503ServiceUnavailable),
            DnsQueryExecutionStatus.Cancelled => Results.StatusCode(ClientClosedRequest),
            _ => Results.StatusCode(StatusCodes.Status500InternalServerError)
        };
    }

    private static bool IsDnsMessageContentType(string? contentType)
    {
        if (string.IsNullOrWhiteSpace(contentType))
            return false;

        return MediaTypeHeaderValue.TryParse(contentType, out var parsed) &&
               string.Equals(parsed.MediaType, DnsMessageMediaType, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<ReadOnlyMemory<byte>> ReadBodyAsync(
        Stream body,
        int maxBytes,
        CancellationToken cancellationToken)
    {
        using var ms = new MemoryStream(Math.Min(maxBytes, 4096));
        var buffer = new byte[Math.Min(8192, maxBytes)];
        while (true)
        {
            var read = await body.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken)
                .ConfigureAwait(false);
            if (read == 0)
                break;

            if (ms.Length + read > maxBytes)
                throw new PayloadTooLargeException();

            ms.Write(buffer, 0, read);
        }

        return ms.ToArray();
    }

    private static IPEndPoint GetClientEndPoint(HttpContext httpContext)
    {
        var remote = httpContext.Connection.RemoteIpAddress ?? IPAddress.Loopback;
        var port = httpContext.Connection.RemotePort;
        return new IPEndPoint(remote, port);
    }

    private static IPEndPoint GetServerEndPoint(HttpContext httpContext)
    {
        var local = httpContext.Connection.LocalIpAddress ?? IPAddress.Loopback;
        var port = httpContext.Connection.LocalPort;
        if (port == 0)
            port = 8080;
        return new IPEndPoint(local, port);
    }

    private sealed class PayloadTooLargeException : Exception;
}
