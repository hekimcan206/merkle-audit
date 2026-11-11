using Microsoft.Extensions.Diagnostics.HealthChecks;
using Npgsql;

namespace MerkleAudit.Server.Persistence;

internal static class PersistenceExtensions
{
    public static IServiceCollection AddPersistence(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("Default")
            ?? throw new InvalidOperationException("Connection string 'Default' is not configured.");

        services.AddSingleton(_ => CreateDataSource(connectionString));
        services.AddSingleton<MigrationRunner>();
        return services;
    }

    public static NpgsqlDataSource CreateDataSource(string connectionString)
    {
        var builder = new NpgsqlDataSourceBuilder(connectionString);

        // An append holds the tree_state row lock for its whole transaction. lock_timeout bounds how long another writer
        // (a second server instance) waits before failing with a retryable 503; the idle timeout stops a stalled session
        // from holding the lock, and with it the whole log, forever.
        builder.ConnectionStringBuilder.Options ??= "-c lock_timeout=5000 -c idle_in_transaction_session_timeout=30000";

        // No Kerberos here; skipping GSS negotiation also stops Npgsql probing for libgssapi, which chiseled images lack.
        builder.ConnectionStringBuilder.GssEncryptionMode = GssEncryptionMode.Disable;

        // A 1,000-entry append sends Bind messages well over 100 KB. With Npgsql's default 8 KiB write buffer it leaves in many
        // socket writes, and on the benchmark host every append over ~8 KiB stalled ~90 ms (batch of 100: 1,042 entries/s;
        // with 256 KiB: 14,589/s, medians in docs/benchmarks.md). A larger buffer sends it in one write. An explicit
        // "Write Buffer Size" in the connection string still wins.
        if (!new System.Data.Common.DbConnectionStringBuilder { ConnectionString = connectionString }.ContainsKey("Write Buffer Size"))
        {
            builder.ConnectionStringBuilder.WriteBufferSize = 256 * 1024;
        }

        return builder.Build();
    }

    public static async Task MigrateDatabaseAsync(this IServiceProvider services, CancellationToken cancellationToken = default) =>
        await services.GetRequiredService<MigrationRunner>().MigrateAsync(cancellationToken);
}

/// <summary>Readiness: can we open a connection and run a trivial query within the probe timeout?</summary>
internal sealed class DatabaseHealthCheck(NpgsqlDataSource dataSource) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            await using var cmd = dataSource.CreateCommand("SELECT 1");
            await cmd.ExecuteScalarAsync(cancellationToken);
            return HealthCheckResult.Healthy();
        }
        catch (NpgsqlException ex)
        {
            return HealthCheckResult.Unhealthy("Database unavailable.", ex);
        }
    }
}
