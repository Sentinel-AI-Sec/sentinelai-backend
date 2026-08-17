using System.Data;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

/// <summary>
/// The SQL Server expression of <see cref="IScanJobClaim"/>: one statement, one winner (SEC-46).
/// </summary>
/// <remarks>
/// <para>
/// <b>Read the statement, not the method.</b> Everything that makes the claim correct is in the
/// SQL, and each piece of it is load-bearing:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <c>UPDATE … OUTPUT</c> — the test (<c>WHERE Status = 'Queued'</c>) and the set
/// (<c>Status = 'Running'</c>) are one statement, so no second reader can observe the row in
/// between. A <c>SELECT</c> then <c>UPDATE</c> would leave exactly that gap.
/// </description></item>
/// <item><description>
/// <c>UPDLOCK</c> — takes the update lock at read time rather than upgrading a shared lock
/// later. Without it two workers can both read the row before either writes, and the upgrade
/// deadlocks instead of one of them losing cleanly.
/// </description></item>
/// <item><description>
/// <c>READPAST</c> — a worker skips rows another worker has locked instead of blocking behind
/// them. With <c>TOP (1)</c> and no <c>READPAST</c>, N workers serialise on the single oldest
/// queued row and the concurrency cap buys nothing.
/// </description></item>
/// <item><description>
/// <c>ROWLOCK</c> — keeps the engine from escalating to a page lock, which would let one
/// worker's claim hide unrelated queued jobs from every other worker.
/// </description></item>
/// <item><description>
/// <c>ORDER BY StartedAt</c> — oldest first, so a busy queue is fair rather than arbitrary.
/// See the note on that column below.
/// </description></item>
/// </list>
/// <para>
/// <b>On <c>StartedAt</c>.</b> The column is set by <c>SubmitScanCommandHandler</c> when the job
/// is accepted, so despite its name it currently records when the job was <em>queued</em>. This
/// statement orders by it and deliberately does not overwrite it: overwriting would destroy the
/// only record of when the job arrived, make the ordering here self-referential, and change what
/// <c>GET /v1/scans/{id}</c> has always reported. Flagged for SEC-05's owner rather than changed
/// here.
/// </para>
/// <para>
/// <b>Raw ADO rather than EF.</b> Two reasons. The tenant query filter would otherwise hide every
/// row from a worker that has no caller yet — the very identity this statement exists to
/// discover — and <c>Status</c> is persisted by name (<c>ScanJobConfiguration</c>), so the
/// comparison is against the enum's string form, which is what the parameters below carry.
/// </para>
/// </remarks>
public sealed class SqlScanJobClaim(SentinelDbContext context) : IScanJobClaim
{
    /// <summary>
    /// The claim. A CTE is used so <c>TOP (1)</c> can be ordered — <c>UPDATE TOP (1)</c> on its
    /// own picks an arbitrary matching row.
    /// </summary>
    private const string Sql = """
        WITH next AS (
            SELECT TOP (1) Id, TenantId, Status
            FROM ScanJobs WITH (UPDLOCK, READPAST, ROWLOCK)
            WHERE Status = @queued
            ORDER BY StartedAt
        )
        UPDATE next
        SET Status = @running
        OUTPUT inserted.Id, inserted.TenantId;
        """;

    public async Task<ClaimedScanJob?> ClaimNextAsync(CancellationToken ct = default)
    {
        var connection = context.Database.GetDbConnection();

        // The scope's DbContext may or may not have opened it already. Leave it as it was found:
        // closing a connection EF still considers open breaks every later query in the scope.
        var openedHere = connection.State != ConnectionState.Open;
        if (openedHere) await connection.OpenAsync(ct);

        try
        {
            await using var command = connection.CreateCommand();
            command.CommandText = Sql;

            AddParameter(command, "@queued", nameof(ScanStatus.Queued));
            AddParameter(command, "@running", nameof(ScanStatus.Running));

            await using var reader = await command.ExecuteReaderAsync(ct);

            // No row means the queue is empty. Not an error, and by far the common case.
            if (!await reader.ReadAsync(ct)) return null;

            return new ClaimedScanJob(reader.GetGuid(0), reader.GetGuid(1));
        }
        finally
        {
            if (openedHere) await connection.CloseAsync();
        }
    }

    private static void AddParameter(IDbCommand command, string name, string value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.DbType = DbType.String;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }
}
