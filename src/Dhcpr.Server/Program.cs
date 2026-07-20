using Dhcpr.Core;
using Dhcpr.Dhcp.Core;
using Dhcpr.Dns.Core;
using Dhcpr.Server.Data;

ThreadPool.GetMaxThreads(out var workerMaxThreads, out _);
ThreadPool.GetMinThreads(out var workerMinThreads, out _);
ThreadPool.SetMaxThreads(workerMaxThreads, 16384);
ThreadPool.SetMinThreads(workerMinThreads, 256);
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();
builder.Services.AddSingleton<WeatherForecastService>();
builder.Services.AddMemoryCache(o =>
{
    o.TrackStatistics = true;
    o.ExpirationScanFrequency = TimeSpan.FromMinutes(5);
});
builder.Services.AddCoreServices();
builder.Services.AddDns(builder.Configuration.GetSection("DNS"));
builder.Services.AddDhcp(builder.Configuration.GetSection("Dhcp"));

var app = builder.Build();

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
