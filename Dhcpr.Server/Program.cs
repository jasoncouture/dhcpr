using Dhcpr.Core;
using Dhcpr.Data;
using Dhcpr.Dhcp.Core;
using Dhcpr.Dns.Core;
using Dhcpr.Server;
using Dhcpr.Server.Data;

using Microsoft.EntityFrameworkCore;

Console.WriteLine("DHCPR Server - Starting...");
Console.WriteLine("Initializing SQLite libraries");
SQLitePCL.Batteries_V2.Init();
Console.WriteLine("Continuing startup");
var builder = WebApplication.CreateBuilder(args);

// builder.Configuration.AddPlatformConfigurationLocations(args);
// // These must be re-added, otherwise config files overwrite them. But env and cli should take precedence over files.
// builder.Configuration.AddEnvironmentVariables();
// builder.Configuration.AddCommandLine(args);

// Add services to the container.
builder.Services.AddDatabaseServices();
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddSingleton<WeatherForecastService>();
builder.Services.AddMemoryCache();
builder.Services.AddCoreServices();
builder.Services.AddDns(builder.Configuration.GetSection("DNS"));
builder.Services.AddDhcp(builder.Configuration.GetSection("DHCP"));

builder.WebHost.ConfigureKestrel(options =>
{
    options.Configure(builder.Configuration.GetSection("Kestrel"), true);
});


var app = builder.Build();
await using (var scope = app.Services.CreateAsyncScope())
{
    scope.ServiceProvider.GetRequiredService<ILogger<Program>>()
        .LogInformation("Updating internal database, if necessary");
    var db = scope.ServiceProvider.GetRequiredService<DataContext>();
    await db.Database.MigrateAsync();
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseStaticFiles();

app.UseRouting();

app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

Console.WriteLine("Application configuration complete, starting services.");
app.Run();