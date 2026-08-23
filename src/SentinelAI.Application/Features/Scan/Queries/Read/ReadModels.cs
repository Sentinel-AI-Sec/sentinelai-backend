using System.Text.Json.Serialization;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Queries.Read;

/// <summary>
/// The wire shapes of the read API (SEC-40), exactly as fixed by
/// <c>SentinelAI_API_Design_V2.1.md</c> §5.3–5.5.
/// </summary>
/// <remarks>
/// <para>
/// <b>These are a contract, not a convenience.</b> The Angular screen (SEC-42) is built against
/// them, so a rename here is a breaking change for another repository — which is why every
/// property carries an explicit <see cref="JsonPropertyNameAttribute"/> rather than relying on a
/// serializer setting. The attribute is the contract, written where it cannot drift from the
/// type it describes, and it survives anyone later changing a global naming policy.
/// </para>
/// <para>
/// Snake case here, camel case on the older endpoints. That inconsistency is deliberate and
/// contained: the design document specifies snake case, the frontend team already has that
/// document, and converting the whole API would change responses that other work depends on.
/// </para>
/// <para>
/// Enums cross the wire as words, never as numbers. <c>"confidence": 2</c> is meaningless to a
/// screen and silently changes meaning if a member is ever inserted into the enum; <c>"certain"</c>
/// does neither.
/// </para>
/// </remarks>
internal static class Wire
{
    /// <summary>
    /// The <c>type</c> vocabulary for graph nodes: <c>pkg | code | image | task | role |
    /// resource</c>.
    /// </summary>
    /// <remarks>
    /// Deliberately <em>not</em> <c>NodeTypeExtensions.Prefix</c>. That is the node-key prefix —
    /// a cross-repo identifier the Action, fixtures and corpus all mirror, where
    /// <see cref="NodeType.Resource"/> is spelled <c>s3</c> for historical reasons. The design
    /// document's <c>type</c> field is a separate, readable vocabulary: a node keyed
    /// <c>s3:customer-data</c> is typed <c>resource</c>. Collapsing the two would either leak
    /// the historical spelling into the UI or break every stored node key.
    /// </remarks>
    public static string Of(NodeType type) => type switch
    {
        NodeType.Pkg => "pkg",
        NodeType.Code => "code",
        NodeType.Image => "image",
        NodeType.Task => "task",
        NodeType.IamRole => "role",
        NodeType.Resource => "resource",
        _ => throw new ArgumentOutOfRangeException(nameof(type), type, "No wire spelling for this node type."),
    };

    public static string Of(Layer layer) => layer.ToString().ToLowerInvariant();
    public static string Of(Confidence confidence) => confidence.ToString().ToLowerInvariant();
    public static string Of(ChainStatus status) => status.ToString().ToLowerInvariant();

    /// <summary>
    /// Job status and pipeline stage, for the list endpoints.
    /// </summary>
    /// <remarks>
    /// The older <c>GET /v1/scans/{id}</c> answers inside the <c>Response</c> envelope and lets
    /// the serializer render these two as integers. The list endpoints do not copy that: a
    /// <c>"status": 2</c> in a table row is meaningless to read and changes meaning the day a
    /// member is inserted into the enum. Both spellings coexist because the poll endpoint's shape
    /// is already depended on and this is a new one — see <c>docs/Read_API.md</c>.
    /// </remarks>
    public static string Of(ScanStatus status) => status.ToString().ToLowerInvariant();

    public static string Of(ScanStage stage) => stage.ToString().ToLowerInvariant();

    /// <summary>
    /// Per-hop verdicts cross the wire as words for the usual reason, and for one more: the two
    /// members that are not verdicts have to be nameable. <c>"blue_verdict": "unattributed"</c>
    /// is something a screen can decline to render; <c>false</c> was not (audit 42-A).
    /// </summary>
    public static string Of(HopVerdict verdict) => verdict.ToString().ToLowerInvariant();

    /// <summary>Seams cross the wire hyphenated: <c>dep-code</c>, <c>infra-spine</c>.</summary>
    public static string Of(Seam seam) => seam switch
    {
        Seam.InfraSpine => "infra-spine",
        Seam.DepCode => "dep-code",
        Seam.CodeInfra => "code-infra",
        Seam.RoleResource => "role-resource",
        _ => throw new ArgumentOutOfRangeException(nameof(seam), seam, "No wire spelling for this seam."),
    };
}

// ---- GET /v1/scans/{id}/bundle ---------------------------------------------------------

/// <summary>Provenance of what the runner actually uploaded (design doc §5.3).</summary>
public sealed record BundleView
{
    [JsonPropertyName("scan_job_id")] public required string ScanJobId { get; init; }
    [JsonPropertyName("runner_secret_scan")] public required string RunnerSecretScan { get; init; }
    [JsonPropertyName("ingress_redaction_applied")] public required bool IngressRedactionApplied { get; init; }
    [JsonPropertyName("artifact_manifest")] public required string ArtifactManifest { get; init; }
    [JsonPropertyName("scanner_versions")] public required string ScannerVersions { get; init; }
    [JsonPropertyName("sha256")] public required string Sha256 { get; init; }
    [JsonPropertyName("size_bytes")] public required long SizeBytes { get; init; }
    [JsonPropertyName("received_at")] public required DateTime ReceivedAt { get; init; }

    /// <summary>
    /// Whether the stored bytes are gone (SEC-35). Reported because the provenance record
    /// outlives the bundle it describes: the manifest and hash stay auditable after the
    /// material itself has been deleted.
    /// </summary>
    [JsonPropertyName("bundle_purged")] public required bool BundlePurged { get; init; }

    public static BundleView From(ScanBundle bundle, bool purged) => new()
    {
        ScanJobId = bundle.ScanJobId.ToString(),
        RunnerSecretScan = bundle.RunnerSecretScan,
        IngressRedactionApplied = bundle.IngressRedactionApplied,
        ArtifactManifest = bundle.ArtifactManifest,
        ScannerVersions = bundle.ScannerVersions,
        Sha256 = bundle.Sha256,
        SizeBytes = bundle.SizeBytes,
        ReceivedAt = bundle.ReceivedAt,
        BundlePurged = purged,
    };
}

// ---- GET /v1/scans/{id}/findings -------------------------------------------------------

/// <summary>One normalized finding.</summary>
public sealed record FindingView
{
    [JsonPropertyName("id")] public required string Id { get; init; }
    [JsonPropertyName("source_tool")] public required string SourceTool { get; init; }
    [JsonPropertyName("layer")] public required string Layer { get; init; }
    [JsonPropertyName("severity")] public required int Severity { get; init; }
    [JsonPropertyName("cwe_id")] public string? CweId { get; init; }
    [JsonPropertyName("cve_id")] public string? CveId { get; init; }
    [JsonPropertyName("node_ref")] public required string NodeRef { get; init; }
    [JsonPropertyName("message")] public required string Message { get; init; }

    /// <summary>
    /// Whether this finding's text was scrubbed on the way in (SEC-33). Surfaced so the screen
    /// can show that a secret was caught rather than leaving the redaction invisible.
    /// </summary>
    [JsonPropertyName("redacted")] public required bool Redacted { get; init; }

    public static FindingView From(Finding finding) => new()
    {
        Id = finding.Id.ToString(),
        SourceTool = finding.SourceTool,
        Layer = Wire.Of(finding.Layer),
        Severity = finding.Severity,
        CweId = finding.CweId,
        CveId = finding.CveId,
        NodeRef = finding.NodeRef,
        Message = finding.Message,
        Redacted = finding.Redacted,
    };
}

// ---- GET /v1/scans/{id}/graph ----------------------------------------------------------

/// <summary>The persisted resource graph (design doc §5.4).</summary>
public sealed record GraphView
{
    [JsonPropertyName("scan_job_id")] public required string ScanJobId { get; init; }
    [JsonPropertyName("nodes")] public required IReadOnlyList<GraphNodeView> Nodes { get; init; }
    [JsonPropertyName("edges")] public required IReadOnlyList<GraphEdgeView> Edges { get; init; }
}

public sealed record GraphNodeView
{
    [JsonPropertyName("node_key")] public required string NodeKey { get; init; }
    [JsonPropertyName("type")] public required string Type { get; init; }
    [JsonPropertyName("layer")] public required string Layer { get; init; }

    /// <summary>Carries a high-severity finding — the seeds traversal starts from.</summary>
    [JsonPropertyName("is_hot")] public required bool IsHot { get; init; }

    public static GraphNodeView From(GraphNode node) => new()
    {
        NodeKey = node.NodeKey,
        Type = Wire.Of(node.NodeType),
        Layer = Wire.Of(node.Layer),
        IsHot = node.IsHot,
    };
}

/// <summary>
/// An edge, addressed by node <em>key</em> rather than by row id.
/// </summary>
/// <remarks>
/// The design document's shape uses keys, and it is the right call: a key is the canonical
/// identity of the thing (SEC-03), stable across scans and meaningful to a human reading the
/// JSON. A row id would force the screen to build a lookup table before it could draw anything.
/// </remarks>
public sealed record GraphEdgeView
{
    [JsonPropertyName("from")] public required string From { get; init; }
    [JsonPropertyName("to")] public required string To { get; init; }
    [JsonPropertyName("relation")] public required string Relation { get; init; }
    [JsonPropertyName("seam")] public required string Seam { get; init; }
    [JsonPropertyName("confidence")] public required string Confidence { get; init; }
    [JsonPropertyName("oriented_attack_dir")] public required bool OrientedAttackDir { get; init; }

    /// <summary>Named <c>Of</c>, not <c>From</c>: this type already has a <c>From</c> property.</summary>
    public static GraphEdgeView Of(GraphEdge edge, IReadOnlyDictionary<Guid, string> keysById) => new()
    {
        From = keysById.TryGetValue(edge.FromNodeId, out var from) ? from : edge.FromNodeId.ToString(),
        To = keysById.TryGetValue(edge.ToNodeId, out var to) ? to : edge.ToNodeId.ToString(),
        Relation = edge.Relation,
        Seam = Wire.Of(edge.Seam),
        Confidence = Wire.Of(edge.Confidence),
        OrientedAttackDir = edge.OrientedAttackDir,
    };
}

// ---- GET /v1/scans/{id}/chains ---------------------------------------------------------

/// <summary>One candidate or adjudicated exploit chain, with its hops in order.</summary>
public sealed record ChainView
{
    [JsonPropertyName("id")] public required string Id { get; init; }
    [JsonPropertyName("priority")] public required int Priority { get; init; }
    [JsonPropertyName("hop_count")] public required int HopCount { get; init; }
    [JsonPropertyName("status")] public required string Status { get; init; }

    /// <summary>
    /// The weakest join anywhere in the chain (AID-01 §3.3). The single most important field
    /// on this object: it is what stops a chain resting on an unresolved guess being read as
    /// certain.
    /// </summary>
    [JsonPropertyName("min_confidence")] public required string MinConfidence { get; init; }

    [JsonPropertyName("hops")] public required IReadOnlyList<ChainHopView> Hops { get; init; }

    public static ChainView From(Chain chain, IReadOnlyDictionary<Guid, string> nodeKeysById) => new()
    {
        Id = chain.Id.ToString(),
        Priority = chain.Priority,
        HopCount = chain.HopCount,
        Status = Wire.Of(chain.Status),
        MinConfidence = Wire.Of(chain.MinConfidence),
        Hops = HopsOf(chain, nodeKeysById),
    };

    /// <summary>
    /// The chain's hops in order, each carrying the node it stands on — including the seed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The seed hop has no edge, and its node key is not recoverable from the row alone.</b>
    /// A hop names its node through <c>edge.to_node_id</c>, which works for every hop the
    /// traversal stepped into and not for hop 0, which arrived from nowhere — <c>edge_id</c> is
    /// null there by design. Read hop-by-hop, the seed's key therefore came back null and the
    /// chain served on the wire began one hop late.
    /// </para>
    /// <para>
    /// That is not cosmetic. The seed is the finding the chain <em>starts</em> from — the
    /// vulnerable package in the flagship chain — so every path the dashboard drew was missing
    /// the dependency layer, and a three-layer claim was rendered as two. Nothing failed:
    /// the graph stage's own response carries the full path, so the two halves disagreed while
    /// each was individually green. SEC-49's harness is what put them side by side.
    /// </para>
    /// <para>
    /// The fix needs the sibling hop rather than more columns: hop 0's node is where hop 1's
    /// edge comes <em>from</em>. That is exact, not inferred — the traversal built the two
    /// together — and it stays correct if hops are ever renumbered, because it reads the next
    /// hop in order rather than assuming the number 1.
    /// </para>
    /// </remarks>
    private static IReadOnlyList<ChainHopView> HopsOf(Chain chain, IReadOnlyDictionary<Guid, string> nodeKeysById)
    {
        var ordered = chain.ChainHops.OrderBy(h => h.HopOrder).ToList();

        return
        [
            .. ordered.Select((hop, index) => ChainHopView.From(
                hop,
                nodeKeysById,
                // Only ever consulted when this hop has no edge of its own.
                nextHop: index + 1 < ordered.Count ? ordered[index + 1] : null)),
        ];
    }
}

public sealed record ChainHopView
{
    [JsonPropertyName("order")] public required int Order { get; init; }

    /// <summary>
    /// The ATT&amp;CK id Red named for this hop, or empty when it named none this scan's brief
    /// could ground (audit 42-A).
    /// </summary>
    /// <remarks>
    /// <b>Empty means there is no technique to link to.</b> It is the normal answer, not a
    /// missing value to be papered over: a renderer that appends this to
    /// <c>https://attack.mitre.org/techniques/</c> unconditionally produces a link to MITRE's
    /// index dressed up as a link to a specific technique, which is what audit 42-A found on
    /// every chain in the product.
    /// </remarks>
    [JsonPropertyName("technique_id")] public required string TechniqueId { get; init; }

    /// <summary>
    /// The narrow question: did Blue confirm this hop? True only for
    /// <see cref="HopVerdict.Confirmed"/>.
    /// </summary>
    /// <remarks>
    /// Kept on the wire because the dashboard is built against it, but it is now derived rather
    /// than stored, and it is the lossy half of this pair. Counting <c>blue_validated</c> across
    /// hops answers "how many did Blue confirm?" and nothing else — in particular a false here
    /// is not a negative finding. <see cref="BlueVerdict"/> is the field that says which kind of
    /// not-confirmed a hop is, and a summary line about a chain should be written from that one.
    /// </remarks>
    [JsonPropertyName("blue_validated")] public required bool BlueValidated { get; init; }

    /// <summary>
    /// What Blue's turn actually said about this hop: <c>unassessed | unattributed | refuted |
    /// unresolved | confirmed</c> (audit 42-A).
    /// </summary>
    /// <remarks>
    /// The two that are not verdicts are the point. <c>unassessed</c> means no debate has run
    /// over this chain; <c>unattributed</c> means Blue's turn was read and nothing in it could be
    /// tied to this hop. Neither is evidence against the hop, and a screen that renders either as
    /// a cross or a failure is stating a result nobody produced. <c>unresolved</c> is Blue's own
    /// "the evidence cannot settle this" — also not a refutation (AID-01 §3.3).
    /// </remarks>
    [JsonPropertyName("blue_verdict")] public required string BlueVerdict { get; init; }

    /// <summary>Null on the seed hop, which arrived from nowhere.</summary>
    [JsonPropertyName("edge_confidence")] public string? EdgeConfidence { get; init; }

    /// <summary>Null where the hop is a place on a path that carries no scanner finding.</summary>
    [JsonPropertyName("finding_id")] public string? FindingId { get; init; }

    /// <summary>
    /// The node this hop stands on. Null only when the graph rows it would be read from are
    /// missing, which is a broken chain rather than a normal one.
    /// </summary>
    [JsonPropertyName("node_key")] public string? NodeKey { get; init; }

    /// <param name="nextHop">
    /// The hop after this one, when there is one. Consulted only for the seed hop, whose own
    /// row cannot name its node — see <see cref="ChainView.HopsOf"/>.
    /// </param>
    public static ChainHopView From(
        ChainHop hop, IReadOnlyDictionary<Guid, string> nodeKeysById, ChainHop? nextHop = null) => new()
    {
        Order = hop.HopOrder,
        TechniqueId = hop.TechniqueId,
        BlueValidated = hop.BlueValidated,
        BlueVerdict = Wire.Of(hop.BlueVerdict),
        EdgeConfidence = hop.Edge is { } edge ? Wire.Of(edge.Confidence) : null,
        FindingId = hop.FindingId?.ToString(),
        NodeKey = NodeKeyOf(hop, nextHop, nodeKeysById),
    };

    /// <summary>
    /// A hop's node: where its own edge arrives, or — for the seed — where the next hop's edge
    /// departs from.
    /// </summary>
    private static string? NodeKeyOf(
        ChainHop hop, ChainHop? nextHop, IReadOnlyDictionary<Guid, string> nodeKeysById)
    {
        if (hop.Edge is { } edge)
            return nodeKeysById.TryGetValue(edge.ToNodeId, out var key) ? key : null;

        return nextHop?.Edge is { } outgoing && nodeKeysById.TryGetValue(outgoing.FromNodeId, out var seed)
            ? seed
            : null;
    }
}

// ---- GET /v1/reports/{id} --------------------------------------------------------------

/// <summary>The draft audit (design doc §5.5).</summary>
public sealed record ReportView
{
    [JsonPropertyName("report_id")] public required string ReportId { get; init; }
    [JsonPropertyName("scan_job_id")] public required string ScanJobId { get; init; }

    /// <summary>
    /// Always <c>draft_audit</c>. AID-01 §7 makes the framing non-negotiable — this is
    /// prioritized material for human review, never a verified verdict — and it is a field on
    /// the wire so a renderer cannot omit the distinction.
    /// </summary>
    [JsonPropertyName("framing")] public required string Framing { get; init; }

    [JsonPropertyName("summary")] public required string Summary { get; init; }
    [JsonPropertyName("corpus_version")] public required string CorpusVersion { get; init; }
    [JsonPropertyName("created_at")] public required DateTime CreatedAt { get; init; }
    [JsonPropertyName("retained")] public required bool Retained { get; init; }
    [JsonPropertyName("chains")] public required IReadOnlyList<ChainView> Chains { get; init; }
    [JsonPropertyName("citations")] public required IReadOnlyList<CitationView> Citations { get; init; }
    [JsonPropertyName("cost")] public required ReportCostView Cost { get; init; }
}

public sealed record CitationView
{
    [JsonPropertyName("knowledge_id")] public required string KnowledgeId { get; init; }
    [JsonPropertyName("source")] public required string Source { get; init; }
    [JsonPropertyName("collection")] public required string Collection { get; init; }

    public static CitationView From(Citation citation) => new()
    {
        KnowledgeId = citation.KnowledgeId,
        Source = citation.Source,
        Collection = citation.Collection,
    };
}

/// <summary>What the audit cost, per SEC-31.</summary>
public sealed record ReportCostView
{
    [JsonPropertyName("currency")] public required string Currency { get; init; }
    [JsonPropertyName("total")] public required decimal Total { get; init; }
    [JsonPropertyName("model_calls")] public required int ModelCalls { get; init; }

    /// <summary>
    /// False when tokens were spent on a tier with no configured price, so <c>total</c> is an
    /// under-count rather than the bill. Surfaced rather than hidden: a missing rate would
    /// otherwise be indistinguishable from a free scan.
    /// </summary>
    [JsonPropertyName("rated")] public required bool Rated { get; init; }

    public static ReportCostView From(Report report) => new()
    {
        Currency = report.CostCurrency,
        Total = report.TotalCost,
        ModelCalls = report.ModelCalls,
        Rated = report.CostRated,
    };
}

// ---- GET /v1/scans/{id}/audit-integrity (admin) -----------------------------------------

/// <summary>
/// The machine-checkable facts about one scan's reasoning.
/// </summary>
/// <remarks>
/// Deliberately absent from the UI's <c>wire.ts</c>. This is an operator surface: it answers "did
/// that run behave", and every field is either self-reported by the pipeline or checked against the
/// graph the same scan built. None of it is a security judgement, and read as one it would mislead.
/// </remarks>
public sealed record AuditIntegrityView
{
    [JsonPropertyName("scan_job_id")] public required string ScanJobId { get; init; }
    [JsonPropertyName("adjudicated")] public required bool Adjudicated { get; init; }
    [JsonPropertyName("outcome")] public required string Outcome { get; init; }
    [JsonPropertyName("rounds")] public required int Rounds { get; init; }
    [JsonPropertyName("verdict_readable")] public required bool VerdictReadable { get; init; }
    [JsonPropertyName("terminated_by_turn_cap")] public required bool TerminatedByTurnCap { get; init; }
    [JsonPropertyName("weakest_join")] public required string WeakestJoin { get; init; }

    [JsonPropertyName("edge_integrity_warnings")] public required int EdgeIntegrityWarnings { get; init; }
    [JsonPropertyName("edge_integrity_detail")] public required IReadOnlyList<string> EdgeIntegrityDetail { get; init; }
    [JsonPropertyName("abandoned_reasoning_warnings")] public required int AbandonedReasoningWarnings { get; init; }
    [JsonPropertyName("abandoned_reasoning_detail")] public required IReadOnlyList<string> AbandonedReasoningDetail { get; init; }

    [JsonPropertyName("retrieval_findings")] public required int RetrievalFindings { get; init; }
    [JsonPropertyName("retrieval_grounded")] public required int RetrievalGrounded { get; init; }
    [JsonPropertyName("coverage_percent")] public required int CoveragePercent { get; init; }
    [JsonPropertyName("modes_that_did_not_fire")] public required IReadOnlyList<string> ModesThatDidNotFire { get; init; }

    [JsonPropertyName("candidate_chains")] public required int CandidateChains { get; init; }
    [JsonPropertyName("chains_adjudicated")] public required int ChainsAdjudicated { get; init; }

    [JsonPropertyName("corpus_version")] public required string CorpusVersion { get; init; }
    [JsonPropertyName("harness_version")] public required int HarnessVersion { get; init; }
    [JsonPropertyName("created_at")] public required DateTime CreatedAt { get; init; }

    public static AuditIntegrityView From(ScanAuditIntegrity row) => new()
    {
        ScanJobId = row.ScanJobId.ToString(),
        Adjudicated = row.Adjudicated,
        Outcome = row.Outcome.ToLowerInvariant(),
        Rounds = row.Rounds,
        VerdictReadable = row.VerdictReadable,
        TerminatedByTurnCap = row.TerminatedByTurnCap,
        WeakestJoin = row.WeakestJoin.ToLowerInvariant(),
        EdgeIntegrityWarnings = row.EdgeIntegrityWarnings,
        EdgeIntegrityDetail = Lines(row.EdgeIntegrityDetail),
        AbandonedReasoningWarnings = row.AbandonedReasoningWarnings,
        AbandonedReasoningDetail = Lines(row.AbandonedReasoningDetail),
        RetrievalFindings = row.RetrievalFindings,
        RetrievalGrounded = row.RetrievalGrounded,
        CoveragePercent = row.CoveragePercent,
        ModesThatDidNotFire = row.ModesThatDidNotFire is { Length: > 0 }
            ? row.ModesThatDidNotFire.Split(',')
            : [],
        CandidateChains = row.CandidateChains,
        ChainsAdjudicated = row.ChainsAdjudicated,
        CorpusVersion = row.CorpusVersion,
        HarnessVersion = row.HarnessVersion,
        CreatedAt = row.CreatedAt,
    };

    /// <summary>
    /// Warnings back out as a list. Stored as one blob, read as items — a reader wants to count
    /// them and a newline-delimited string makes that the caller's problem.
    /// </summary>
    private static IReadOnlyList<string> Lines(string stored) =>
        string.IsNullOrEmpty(stored) ? [] : stored.Split('\n');
}
