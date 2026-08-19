using SentinelAI.Api;
using SentinelAI.Application;
using SentinelAI.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddApplicationServices()
    .AddInfrastructureServices(builder.Configuration)
    .AddApiServices(builder.Configuration);

var app = builder.Build();

app.UseApiServices();

app.Run();

// Exposed so WebApplicationFactory<Program> can boot this app in tests.
public partial class Program;