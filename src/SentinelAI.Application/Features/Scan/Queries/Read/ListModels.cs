using System.Text.Json.Serialization;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Queries.Read;

// The wire shapes of the list endpoints. Same rules as ReadModels.cs, and for the same reason:
// snake_case spelled out in an explicit [JsonPropertyName] on every property, enums crossing the
// wire as words, and no field the caller's own token did not already tell them (no tenant_id).

// ---- GET /v1/scans ---------------------------------------------------------------------

/// <summary>
/// One scan in the history list.
/// </summary>
/// <remarks>
/// <para>
/// A superset of <c>ScanJobResponse</c> (the shape <c>GET /v1/scans/{id}</c> polls), plus the
/// three fields that make a row identifiable without a second request: <see cref="RepoUrl"/>,
/// <see cref="PrRef"/> and <see cref="CommitSha"/>. A list of bare GUIDs is not a history —
/// nobody recognises their own scan by its id, and requiring one round trip per row to find out
/// which repository it was would make the console slower than the local index it replaces.
/// </para>
/// <para>
/// <see cref="RepoUrl"/> is joined from the project rather than stored on the job, so it is the
/// repository's URL <em>now</em>. That is the right answer for a list whose purpose is
/// recognition; the provenance of what was actually scanned lives in
/// <c>GET /v1/scans/{id}/bundle</c> and is immutable.
/// </para>
/// </remarks>
public sealed record ScanListItemView
{
    [JsonPropertyName("scan_job_id")] public required string ScanJobId { get; init; }
    [JsonPropertyName("project_id")] public required string ProjectId { get; init; }

    /// <summary>The project's repository. Empty if the project row is gone.</summary>
    [JsonPropertyName("repo_url")] public required string RepoUrl { get; init; }

    [JsonPropertyName("pr_ref")] public required string PrRef { get; init; }
    [JsonPropertyName("commit_sha")] public required string CommitSha { get; init; }
    [JsonPropertyName("status")] public required string Status { get; init; }
    [JsonPropertyName("stage")] public required string Stage { get; init; }

    /// <summary>
    /// The audit this scan produced, or null. Null has two meanings — the audit stage has not run
    /// yet, and the submitter did not ask to keep its report (SEC-35) — which <see cref="Status"/>
    /// and <see cref="Stage"/> together distinguish.
    /// </summary>
    [JsonPropertyName("report_id")] public string? ReportId { get; init; }

    [JsonPropertyName("bundle_purged")] public required bool BundlePurged { get; init; }
    [JsonPropertyName("corpus_version")] public required string CorpusVersion { get; init; }

    /// <summary>Why the pipeline stopped, on a failed scan. Null otherwise.</summary>
    [JsonPropertyName("failure_reason")] public string? FailureReason { get; init; }

    [JsonPropertyName("started_at")] public required DateTime StartedAt { get; init; }
    [JsonPropertyName("completed_at")] public DateTime? CompletedAt { get; init; }

    public static ScanListItemView From(ScanJob job) => new()
    {
        ScanJobId = job.Id.ToString(),
        ProjectId = job.ProjectId.ToString(),
        RepoUrl = job.Project?.RepoUrl ?? string.Empty,
        PrRef = job.PrRef,
        CommitSha = job.CommitSha,
        Status = Wire.Of(job.Status),
        Stage = Wire.Of(job.Stage),
        ReportId = job.Report?.Id.ToString(),
        BundlePurged = job.BundlePurged,
        CorpusVersion = job.CorpusVersion,
        FailureReason = job.FailureReason,
        StartedAt = job.StartedAt,
        CompletedAt = job.CompletedAt,
    };
}

// ---- GET /v1/reports -------------------------------------------------------------------

/// <summary>
/// One draft audit in the list, without its chains or citations.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Framing"/> is carried on every row and not only on the full report. AID-01 §7 makes
/// the draft framing non-negotiable, and a list is exactly where it would otherwise be dropped:
/// a screen showing twenty audits with no framing on any of them is where "candidate chains a
/// debate argued over" quietly becomes "twenty findings".
/// </para>
/// <para>
/// The chains are not included. They are the bulk of a report and the reason
/// <c>GET /v1/reports/{id}</c> exists; embedding them here would turn a page of twenty rows into
/// twenty full audits, and no list screen renders them.
/// </para>
/// </remarks>
public sealed record ReportListItemView
{
    [JsonPropertyName("report_id")] public required string ReportId { get; init; }
    [JsonPropertyName("scan_job_id")] public required string ScanJobId { get; init; }
    [JsonPropertyName("project_id")] public required string ProjectId { get; init; }
    [JsonPropertyName("repo_url")] public required string RepoUrl { get; init; }
    [JsonPropertyName("pr_ref")] public required string PrRef { get; init; }
    [JsonPropertyName("commit_sha")] public required string CommitSha { get; init; }

    /// <summary>Always <c>draft_audit</c>. See the remarks on this type.</summary>
    [JsonPropertyName("framing")] public required string Framing { get; init; }

    [JsonPropertyName("summary")] public required string Summary { get; init; }
    [JsonPropertyName("corpus_version")] public required string CorpusVersion { get; init; }
    [JsonPropertyName("retained")] public required bool Retained { get; init; }
    [JsonPropertyName("created_at")] public required DateTime CreatedAt { get; init; }
    [JsonPropertyName("cost")] public required ReportCostView Cost { get; init; }

    public static ReportListItemView From(Report report, ScanJob? job) => new()
    {
        ReportId = report.Id.ToString(),
        ScanJobId = report.ScanJobId.ToString(),
        ProjectId = job?.ProjectId.ToString() ?? string.Empty,
        RepoUrl = job?.Project?.RepoUrl ?? string.Empty,
        PrRef = job?.PrRef ?? string.Empty,
        CommitSha = job?.CommitSha ?? string.Empty,
        Framing = report.Framing,
        Summary = report.Summary,
        CorpusVersion = job?.CorpusVersion ?? string.Empty,
        Retained = report.Retained,
        CreatedAt = report.CreatedAt,
        Cost = ReportCostView.From(report),
    };
}

// ---- GET /v1/scans/{id}/summary --------------------------------------------------------

/// <summary>
/// What one scan holds, counted.
/// </summary>
/// <remarks>
/// Every number here is a <c>COUNT</c> over the same tenant-scoped predicate the corresponding
/// paged endpoint filters on, so this and a full walk of that endpoint's pages agree by
/// construction. Nothing is estimated and nothing is derived from a sample.
/// </remarks>
public sealed record ScanSummaryView
{
    [JsonPropertyName("scan_job_id")] public required string ScanJobId { get; init; }
    [JsonPropertyName("status")] public required string Status { get; init; }
    [JsonPropertyName("stage")] public required string Stage { get; init; }
    [JsonPropertyName("report_id")] public string? ReportId { get; init; }
    [JsonPropertyName("findings")] public required FindingsSummaryView Findings { get; init; }
    [JsonPropertyName("graph")] public required GraphSummaryView Graph { get; init; }
    [JsonPropertyName("chains")] public required ChainsSummaryView Chains { get; init; }
}

/// <summary>Findings on this scan, bucketed the two ways the findings screen filters them.</summary>
public sealed record FindingsSummaryView
{
    [JsonPropertyName("total")] public required int Total { get; init; }

    /// <summary>Keyed <c>code</c> / <c>dep</c> / <c>infra</c>. Every layer is present, including
    /// the ones at zero — a missing key and a zero would otherwise be indistinguishable, and a
    /// filter chip cannot be rendered as "empty" if the API never mentions it.</summary>
    [JsonPropertyName("by_layer")] public required IReadOnlyDictionary<string, int> ByLayer { get; init; }

    /// <summary>Keyed <c>"0"</c>–<c>"4"</c>, all five buckets always present.</summary>
    [JsonPropertyName("by_severity")] public required IReadOnlyDictionary<string, int> BySeverity { get; init; }

    /// <summary>Highest severity present, or null when the scan has no findings at all. Null
    /// rather than 0, because 0 is a real severity a finding can carry.</summary>
    [JsonPropertyName("max_severity")] public int? MaxSeverity { get; init; }

    /// <summary>How many findings had a secret scrubbed out of them on the way in (SEC-33).</summary>
    [JsonPropertyName("redacted")] public required int Redacted { get; init; }
}

/// <summary>The resource graph's size, and how much of it rests on inference.</summary>
public sealed record GraphSummaryView
{
    [JsonPropertyName("nodes")] public required int Nodes { get; init; }
    [JsonPropertyName("edges")] public required int Edges { get; init; }

    /// <summary>Nodes carrying a high-severity finding — the seeds traversal starts from.</summary>
    [JsonPropertyName("hot_nodes")] public required int HotNodes { get; init; }

    /// <summary>
    /// Edges keyed <c>certain</c> / <c>inferred</c> / <c>unresolved</c>, all three always present.
    /// </summary>
    /// <remarks>
    /// Reported as three counts rather than one "average confidence". The tiers are not points on
    /// a scale to be averaged: <c>unresolved</c> means the join could not be settled, which is a
    /// different statement from <c>inferred</c> rather than a worse one, and any single number
    /// mixing them asserts an ordering the product spends its whole UI refusing to assert.
    /// </remarks>
    [JsonPropertyName("edges_by_confidence")]
    public required IReadOnlyDictionary<string, int> EdgesByConfidence { get; init; }
}

/// <summary>Candidate chains on this scan, and how the debate left them.</summary>
public sealed record ChainsSummaryView
{
    [JsonPropertyName("total")] public required int Total { get; init; }

    /// <summary>Keyed <c>candidate</c> / <c>asserted</c> / <c>validated</c> / <c>rejected</c>,
    /// all four always present.</summary>
    [JsonPropertyName("by_status")] public required IReadOnlyDictionary<string, int> ByStatus { get; init; }

    /// <summary>
    /// The weakest join in the whole scan — the lowest <c>min_confidence</c> across every chain,
    /// or null when there are no chains.
    /// </summary>
    /// <remarks>
    /// A ceiling on what this scan can claim, and the one number on this object that is a
    /// judgement rather than a count. Reported so a console can caveat a scan-level headline the
    /// same way a chain card caveats a chain.
    /// </remarks>
    [JsonPropertyName("weakest_join")] public string? WeakestJoin { get; init; }
}

/// <summary>
/// Builds the fixed-key count dictionaries above.
/// </summary>
/// <remarks>
/// Every bucket of the enum is seeded at zero before the observed counts are folded in. That is
/// the whole point of the helper: a <c>GROUP BY</c> returns rows only for values that occurred,
/// and a client reading <c>by_layer["infra"]</c> on a scan with no infra findings should get 0,
/// not a missing key it has to defend against.
/// </remarks>
internal static class Buckets
{
    public static Dictionary<string, int> Of<TEnum>(
        IEnumerable<TEnum> all, Func<TEnum, string> spell, IReadOnlyDictionary<TEnum, int> counted)
        where TEnum : struct, Enum
    {
        var buckets = all.ToDictionary(spell, _ => 0);

        foreach (var (value, count) in counted)
            buckets[spell(value)] = count;

        return buckets;
    }

    /// <summary>The 0–4 severity buckets, keyed as strings because JSON object keys are strings.</summary>
    public static Dictionary<string, int> Severity(IReadOnlyDictionary<int, int> counted)
    {
        var buckets = Enumerable.Range(0, 5).ToDictionary(s => s.ToString(), _ => 0);

        foreach (var (severity, count) in counted)
        {
            // A severity outside 0–4 should be impossible — normalization clamps — but a row that
            // got in some other way must not throw a KeyNotFoundException on a read endpoint.
            var key = severity.ToString();
            buckets[key] = buckets.TryGetValue(key, out var existing) ? existing + count : count;
        }

        return buckets;
    }
}
