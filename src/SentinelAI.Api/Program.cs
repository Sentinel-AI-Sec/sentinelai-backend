using SentinelAI.Api;
using SentinelAI.Api.Configuration;
using SentinelAI.Application;
using SentinelAI.Infrastructure;

var builder = WebApplication.CreateBuilder(args);

// SEC-35 (audit 35-A): secrets from Azure Key Vault, layered over the committed settings so the
// vault wins. A no-op — no client, no credential, no network — when KeyVault:Uri is empty, which
// is how every test, the offline demo and a fresh clone run.
//
// Before AddInfrastructureServices, and that ordering is load-bearing rather than tidy: the
// model options, the egress catalog and the pricing table are all read eagerly at registration
// time, so a vault layered on afterwards would be read by nothing that matters and the boot-time
// provider check would still fail on an absent key.
var keyVault = builder.Configuration.AddSentinelKeyVault();

builder.Services
    .AddApplicationServices()
    .AddInfrastructureServices(builder.Configuration)
    .AddApiServices(builder.Configuration);

// Reported through DI rather than logged here: there is no logger until the host is built, and
// what a reader needs is the line in the application log, not one on stdout before it starts.
builder.Services.AddSingleton(keyVault);

var app = builder.Build();

app.UseApiServices();

app.Run();

// Exposed so WebApplicationFactory<Program> can boot this app in tests.
public partial class Program;
