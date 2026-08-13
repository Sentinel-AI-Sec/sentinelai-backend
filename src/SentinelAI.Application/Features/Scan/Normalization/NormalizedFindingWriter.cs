using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Normalization;

/// <summary>
/// Persists one normalization run's unified findings as <c>findings</c> rows, replacing whatever
/// a previous run of the same job left behind.
/// </summary>
/// <remarks>
/// <para>
/// The normalization pipeline is pure — it reads a bundle and returns a list. That was fine for
/// as long as nothing downstream needed a finding to have an identity in the database, and it
/// stopped being fine at SEC-20: a <see cref="ChainHop"/> points at the finding that decorates
/// its node, and a foreign key cannot point at an object that only exists in memory. Running the
/// graph stage against an empty <c>findings</c> table failed the whole chain batch on
/// <c>FK_ChainHops_Findings_FindingId</c>.
/// </para>
/// <para>
/// Note what is <em>not</em> saved: <see cref="Finding.CheckId"/> and
/// <see cref="Finding.Location"/> are mapped out of the schema by design (see
/// <c>FindingConfiguration</c>), so the in-memory list stays the richer one. That is why callers
/// keep passing their own list to the graph stage instead of reading these rows back — the
/// infra-finding locator needs the line numbers that the table does not hold.
/// </para>
/// </remarks>
public sealed class NormalizedFindingWriter(IUnitOfWork unitOfWork, ILogger<NormalizedFindingWriter> logger)
{
    /// <summary>
    /// Replaces the job's persisted findings — and anything that referenced them — with this run's.
    /// </summary>
    public async Task WriteAsync(IReadOnlyList<Finding> findings, Guid scanJobId, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var cleared = await ClearPreviousRunAsync(scanJobId);

        if (findings.Count > 0)
            await unitOfWork.Repository<Finding>().AddRangeAsync([.. findings]);

        await unitOfWork.CompleteAsync();

        logger.LogInformation(
            "Persisted {Count} finding(s) for scan job {ScanJobId}, replacing {Cleared} from a previous run",
            findings.Count, scanJobId, cleared);
    }

    /// <summary>
    /// Deletes the job's findings and the chain rows hanging off them.
    /// </summary>
    /// <remarks>
    /// Re-running a stage by hand is the normal way this endpoint is used, so a second run has to
    /// replace the first rather than pile a duplicate set of findings and chains on top of it.
    /// The deletes go out in one <c>SaveChanges</c> with the inserts; EF orders them by the
    /// foreign keys, so citations go before hops, hops before chains, and chains before findings.
    /// </remarks>
    private async Task<int> ClearPreviousRunAsync(Guid scanJobId)
    {
        var chains = (await unitOfWork.Repository<Chain>()
            .GetWhereAsync(c => c.ScanJobId == scanJobId)).ToList();

        if (chains.Count > 0)
        {
            var chainIds = chains.Select(c => c.Id).ToHashSet();

            var hops = (await unitOfWork.Repository<ChainHop>()
                .GetWhereAsync(h => chainIds.Contains(h.ChainId))).ToList();

            if (hops.Count > 0)
            {
                var hopIds = hops.Select(h => h.Id).ToHashSet();

                var citations = (await unitOfWork.Repository<Citation>()
                    .GetWhereAsync(c => c.ChainHopId != null && hopIds.Contains(c.ChainHopId.Value))).ToList();

                if (citations.Count > 0)
                    await unitOfWork.Repository<Citation>().DeleteRangeAsync(citations);

                await unitOfWork.Repository<ChainHop>().DeleteRangeAsync(hops);
            }

            await unitOfWork.Repository<Chain>().DeleteRangeAsync(chains);
        }

        var stale = (await unitOfWork.Repository<Finding>()
            .GetWhereAsync(f => f.ScanJobId == scanJobId)).ToList();

        if (stale.Count > 0)
            await unitOfWork.Repository<Finding>().DeleteRangeAsync(stale);

        return stale.Count;
    }
}
