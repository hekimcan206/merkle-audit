using MerkleAudit.Server.Log;
using MerkleAudit.Server.Persistence;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using Testcontainers.PostgreSql;

[assembly: AssemblyFixture(typeof(MerkleAudit.IntegrationTests.Infrastructure.LogEnvironment))]

namespace MerkleAudit.IntegrationTests.Infrastructure;

/// <summary>
/// One PostgreSQL 17 container per test run, initialised with the exact role script docker compose uses and migrated
/// as <c>audit_migrator</c> into a template database. A log is a single growing tree, so every test gets its own
/// database cloned from that template (milliseconds) and its own in-memory server connecting as <c>audit_app</c>.
/// </summary>
public sealed class LogEnvironment : IAsyncLifetime
{
    public const string ApiKey = "append-test-only";
    private const string Template = "merkleaudit";
    private const string MigratorPassword = "migrator-test";
    private const string AppPassword = "app-test";
    private const string ReaderPassword = "reader-test";
    private int _databases;

    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder("postgres:17-alpine")
        .WithDatabase(Template)
        .WithEnvironment("MIGRATOR_PASSWORD", MigratorPassword)
        .WithEnvironment("APP_PASSWORD", AppPassword)
        .WithEnvironment("READER_PASSWORD", ReaderPassword)
        .WithResourceMapping(
            File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "postgres-init", "01-roles.sh")),
            "/docker-entrypoint-initdb.d/01-roles.sh")
        .Build();

    public string KeyDirectory { get; } = Directory.CreateTempSubdirectory("merkle-audit-keys-").FullName;

    public async ValueTask InitializeAsync()
    {
        await _postgres.StartAsync();
        await using (var dataSource = PersistenceExtensions.CreateDataSource(ConnectionString(Template, "audit_migrator", MigratorPassword)))
        {
            await new MigrationRunner(dataSource, NullLogger<MigrationRunner>.Instance).MigrateAsync();
        }

        // Nobody may stay connected to a template while it is cloned.
        NpgsqlConnection.ClearAllPools();
        SigningKeyRing.EnsureKey(KeyDirectory);
    }

    public async ValueTask DisposeAsync()
    {
        await _postgres.DisposeAsync();
        Directory.Delete(KeyDirectory, recursive: true);
    }

    /// <summary>A fresh, empty, migrated log database with a server in front of it.</summary>
    public async Task<TestLog> CreateLogAsync(TimeProvider? time = null, Action<IWebHostBuilder>? configure = null)
    {
        var name = $"log_{Interlocked.Increment(ref _databases)}";
        await using (var admin = NpgsqlDataSource.Create(ConnectionString("postgres", null, null)))
        await using (var cmd = admin.CreateCommand($"CREATE DATABASE {name} TEMPLATE {Template}"))
        {
            await cmd.ExecuteNonQueryAsync();
        }

        var factory = new ServerFactory(ConnectionString(name, "audit_app", AppPassword), Path.Combine(KeyDirectory, "sth-signing.pem"), time, configure);
        return new TestLog(
            factory,
            NpgsqlDataSource.Create(ConnectionString(name, null, null)),
            NpgsqlDataSource.Create(ConnectionString(name, "audit_app", AppPassword)),
            NpgsqlDataSource.Create(ConnectionString(name, "audit_migrator", MigratorPassword)),
            Path.Combine(KeyDirectory, "trusted"));
    }

    private string ConnectionString(string database, string? username, string? password)
    {
        var builder = new NpgsqlConnectionStringBuilder(_postgres.GetConnectionString())
        {
            Database = database,
            MaxPoolSize = 40,
            // Generous connect timeout: the host is shared with other projects' containers.
            Timeout = 60,
        };
        if (username is not null)
        {
            builder.Username = username;
            builder.Password = password;
        }

        return builder.ConnectionString;
    }

    internal sealed class ServerFactory(string connectionString, string keyFile, TimeProvider? time, Action<IWebHostBuilder>? configure) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Testing");
            builder.UseSetting("ConnectionStrings:Default", connectionString);
            builder.UseSetting("Signing:KeyFile", keyFile);
            builder.UseSetting("Log:AppendApiKeys:0", ApiKey);
            builder.UseSetting("Log:PublishInterval", "00:00:00");
            builder.UseSetting("Database:MigrateOnStartup", "false");
            builder.UseSetting("Serilog:MinimumLevel:Default", "Warning");
            builder.UseSetting("Serilog:MinimumLevel:Override:Microsoft.Hosting.Lifetime", "Warning");
            if (time is not null)
            {
                builder.ConfigureTestServices(services => services.AddSingleton(time));
            }

            configure?.Invoke(builder);
        }
    }
}
