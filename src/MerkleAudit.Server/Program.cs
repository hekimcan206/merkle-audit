using System.Diagnostics;
using MerkleAudit.Server.Api;
using MerkleAudit.Server.Infrastructure;
using MerkleAudit.Server.Log;
using MerkleAudit.Server.Persistence;
using Scalar.AspNetCore;
using Serilog;

// `--ensure-key <dir>` runs before the host is built: it needs no database or configuration, and the compose demo
// uses it as a one-shot step that creates the signing key on first start.
if (args is ["--ensure-key", var keyDirectory])
{
    Console.WriteLine($"tree-head signing key: {SigningKeyRing.EnsureKey(keyDirectory)}");
    return;
}

var builder = WebApplication.CreateBuilder(args);

builder.AddObservability();
builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = 4 * 1024 * 1024);

builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddPersistence(builder.Configuration);
builder.Services.Configure<LogOptions>(builder.Configuration.GetSection(LogOptions.Section));
builder.Services.Configure<SigningOptions>(builder.Configuration.GetSection(SigningOptions.Section));
builder.Services.AddSingleton<LogStore>();
builder.Services.AddSingleton<GroupCommitWriter>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<GroupCommitWriter>());
builder.Services.AddSingleton<SigningKeyRing>();
builder.Services.AddSingleton<TreeHeadPublisher>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<TreeHeadPublisher>());

builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("database", tags: [HealthEndpoints.ReadyTag]);

// RFC 9457 problem details for every error, with the trace id so a reported error can be found in traces.
builder.Services.AddProblemDetails(options => options.CustomizeProblemDetails = context =>
    context.ProblemDetails.Extensions.TryAdd("traceId", Activity.Current?.TraceId.ToString() ?? context.HttpContext.TraceIdentifier));
builder.Services.AddExceptionHandler<DatabaseExceptionHandler>();

builder.Services.AddOpenApi("v1", options => options.AddDocumentTransformer((document, _, _) =>
{
    document.Info.Title = "merkle-audit";
    document.Info.Version = "v1";
    document.Info.Description = "Tamper-evident audit log: RFC 6962 Merkle tree, inclusion and consistency proofs, signed tree heads.";
    return Task.CompletedTask;
}));

var app = builder.Build();

if (args.Contains("--migrate-only"))
{
    await app.Services.MigrateDatabaseAsync();
    return;
}

app.UseExceptionHandler();
app.UseStatusCodePages();
app.UseSerilogRequestLogging(options => options.GetLevel = (context, _, exception) =>
    exception is null && context.Response.StatusCode < 400 && context.Request.Path.StartsWithSegments("/health")
        ? Serilog.Events.LogEventLevel.Verbose
        : Serilog.Events.LogEventLevel.Information);

if (app.Configuration.GetValue<bool>("OpenApi:Enabled"))
{
    app.MapOpenApi();
    app.MapScalarApiReference(options => options.WithTitle("merkle-audit"));
}

app.MapHealthEndpoints();
app.MapGroup("/api/v1").WithGroupName("v1").MapLogEndpoints();

if (app.Configuration.GetValue<bool>("Database:MigrateOnStartup"))
{
    await app.Services.MigrateDatabaseAsync();
}

await app.RunAsync();

/// <summary>Entry point; public so WebApplicationFactory can boot the app in integration tests.</summary>
public partial class Program;
