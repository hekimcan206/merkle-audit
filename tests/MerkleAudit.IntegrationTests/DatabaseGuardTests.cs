using MerkleAudit.IntegrationTests.Infrastructure;
using Npgsql;

namespace MerkleAudit.IntegrationTests;

/// <summary>
/// Prevention where the database can provide it: the application role cannot rewrite history, and the append-only
/// triggers stop even the schema owner. The superuser can still bypass both, which is why detection exists.
/// </summary>
public sealed class DatabaseGuardTests(LogEnvironment env)
{
    private static async Task<TestLog> SeededAsync(LogEnvironment env)
    {
        var log = await env.CreateLogAsync();
        (await log.AppendBatchAsync([new { actor = "a", action = "b", resource = "c", payload = 1 }, new { actor = "a", action = "b", resource = "c", payload = 2 }]))
            .EnsureSuccessStatusCode();
        await log.PublishAsync();
        return log;
    }

    private static async Task ExecAsync(NpgsqlDataSource dataSource, string sql)
    {
        await using var cmd = dataSource.CreateCommand(sql);
        await cmd.ExecuteNonQueryAsync();
    }

    [Theory]
    [InlineData("UPDATE audit.entries SET payload = '3' WHERE seq = 0")]
    [InlineData("DELETE FROM audit.entries WHERE seq = 0")]
    [InlineData("UPDATE audit.tree_nodes SET hash = hash WHERE level = 0")]
    [InlineData("DELETE FROM audit.tree_heads")]
    [InlineData("TRUNCATE audit.entries")]
    public async Task Application_role_cannot_rewrite_history(string sql)
    {
        await using var log = await SeededAsync(env);

        var act = () => ExecAsync(log.App, sql);

        (await act.Should().ThrowAsync<PostgresException>()).Which.SqlState.Should().Be(PostgresErrorCodes.InsufficientPrivilege);
    }

    [Theory]
    [InlineData("UPDATE audit.entries SET payload = '3' WHERE seq = 0", "audit.entries is append-only (UPDATE rejected)")]
    [InlineData("DELETE FROM audit.tree_nodes WHERE level = 0 AND idx = 0", "audit.tree_nodes is append-only (DELETE rejected)")]
    [InlineData("TRUNCATE audit.tree_heads", "audit.tree_heads is append-only (TRUNCATE rejected)")]
    public async Task Triggers_stop_even_the_table_owner(string sql, string message)
    {
        await using var log = await SeededAsync(env);

        var act = () => ExecAsync(log.Migrator, sql);

        (await act.Should().ThrowAsync<PostgresException>()).Which.MessageText.Should().Be(message);
    }

    [Fact]
    public async Task Superuser_can_bypass_both_and_only_the_verifier_notices()
    {
        await using var log = await SeededAsync(env);
        await using (var conn = await log.Superuser.OpenConnectionAsync())
        {
            await using var cmd = new NpgsqlCommand("SET session_replication_role = replica; UPDATE audit.entries SET payload = '3' WHERE seq = 0", conn);
            await cmd.ExecuteNonQueryAsync();
        }

        var report = await new Verifier.LogAuditor(log.Source, log.Trust).AuditAsync(null, CancellationToken.None);

        report.Findings.Should().ContainSingle(f => f.Kind == Verifier.FindingKind.RowAltered && f.Index == 0);
    }

    [Fact]
    public async Task Application_role_cannot_read_migration_history_or_create_objects()
    {
        await using var log = await SeededAsync(env);

        var readAdmin = () => ExecAsync(log.App, "SELECT * FROM audit_admin.schema_migrations");
        var create = () => ExecAsync(log.App, "CREATE TABLE audit.shadow (x int)");

        (await readAdmin.Should().ThrowAsync<PostgresException>()).Which.SqlState.Should().Be(PostgresErrorCodes.InsufficientPrivilege);
        (await create.Should().ThrowAsync<PostgresException>()).Which.SqlState.Should().Be(PostgresErrorCodes.InsufficientPrivilege);
    }

    [Fact]
    public async Task Publisher_refuses_to_sign_a_tree_rewritten_since_the_last_head()
    {
        await using var log = await SeededAsync(env);
        (await log.AppendAsync(new { actor = "a", action = "b", resource = "c", payload = 3 })).EnsureSuccessStatusCode();
        await new Demo.Tamperer(log.Superuser).RewriteRowAndTreeAsync(0, "someone-else");

        var signed = await log.Publisher.PublishAsync(force: true, CancellationToken.None);

        signed.Should().BeNull("the stored nodes no longer reproduce the root signed at size 2");
        (await log.Source.GetTreeHeadsAsync(CancellationToken.None)).Select(h => h.TreeSize).Should().Equal([2L], "no head was added");
    }
}
