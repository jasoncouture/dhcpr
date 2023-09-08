// See https://aka.ms/new-console-template for more information

using Dhcpr.Core;
using Dhcpr.Dhcp.Core;
using Dhcpr.Dns.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);

// Handle SIGINT and shutdown gracefully.
var shutdownTokenSource = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = false;
    shutdownTokenSource.Cancel();
};


var dnsConfiguration = builder.Configuration.GetDnsConfiguration();
builder.Services.AddDns(dnsConfiguration);

var app = builder.Build();


await app.StartAsync(shutdownTokenSource.Token);
Console.WriteLine("Server started, press ctrl+c to shutdown");

await app.WaitForShutdownAsync(shutdownTokenSource.Token);

