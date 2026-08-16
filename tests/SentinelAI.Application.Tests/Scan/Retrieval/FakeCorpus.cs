using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// One point in the fake corpus — the payload fields SEC-22 filters or reads.
/// </summary>
internal sealed record CorpusPoint(
    string ChunkId,
    KnowledgeSource Source,
    KnowledgeContentType ContentType,
    KnowledgeCollection[] Routing,
    string Title,
    string Text,
    string? CveId = null,
    string? CweId = null,
    string? TechniqueId = null);

/// <summary>
/// An in-memory stand-in for the Qdrant corpus that reproduces the two behaviours SEC-22 exists
/// to handle.
/// </summary>
/// <remarks>
/// <para>
/// <b>1. CWE-tagged CVEs outnumber the weakness definition.</b> Twenty NVD chunks carry
/// <c>cwe_id=CWE-502</c> against two real CWE chunks. That is
/// <c>PIPELINE_A_CONTEXT.md</c> §4's measured 825-versus-2 in miniature, and it is what makes
/// the mandatory <c>source</c> condition testable rather than merely documented.
/// </para>
/// <para>
/// <b>2. NVD drowns OWASP on an unfiltered query.</b> The NVD chunks are written to score well on
/// remediation-shaped wording, so a search that reached the corpus without a filter would return
/// CVEs — the ranking problem §4 describes, reproduced at 20-to-2 instead of 26,283-to-172.
/// </para>
/// <para>
/// Scoring is deterministic token overlap, not a real embedding. That is enough: SEC-22's
/// decisions are about which filter is applied and which arm answers, never about how good the
/// ranking is.
/// </para>
/// </remarks>
internal sealed class FakeCorpus : IKnowledgeSearch
{
    public const string CorpusVersion = "2026-08-10-1143";

    /// <summary>Every exact lookup this corpus was asked, so a test can assert the filter shape.</summary>
    public List<ExactLookup> ExactLookups { get; } = [];

    /// <summary>Every semantic query, paired with the vectors it was given.</summary>
    public List<(SemanticQuery Query, QueryVectors Vectors)> Searches { get; } = [];

    private readonly List<CorpusPoint> _points = [.. Build()];

    public Task<IReadOnlyList<KnowledgeChunk>> ExactAsync(ExactLookup lookup, CancellationToken ct = default)
    {
        ExactLookups.Add(lookup);

        var matches = _points
            .Where(p => p.Routing.Contains(lookup.Collection))

            // Both conditions, exactly as the real filter does. Dropping the source half here
            // would make the fake more permissive than Qdrant and hide the bug it exists to catch.
            .Where(p => p.Source == lookup.Source)
            .Where(p => lookup.Field switch
            {
                CorpusFields.CveId => string.Equals(p.CveId, lookup.Value, StringComparison.OrdinalIgnoreCase),
                CorpusFields.CweId => string.Equals(p.CweId, lookup.Value, StringComparison.OrdinalIgnoreCase),
                _ => false,
            })
            .Select(p => ToChunk(p, score: 0f))
            .ToList();

        return Task.FromResult<IReadOnlyList<KnowledgeChunk>>(matches);
    }

    public Task<IReadOnlyList<KnowledgeChunk>> SearchAsync(
        SemanticQuery query, QueryVectors vectors, CancellationToken ct = default)
    {
        Searches.Add((query, vectors));

        var terms = Tokenize(query.Text);

        var ranked = _points
            .Where(p => p.Routing.Contains(query.Collection))
            .Where(p => query.Sources.Count == 0 || query.Sources.Contains(p.Source))
            .Where(p => query.ContentTypes.Count == 0 || query.ContentTypes.Contains(p.ContentType))
            .Select(p => (Point: p, Score: Overlap(terms, p)))
            .Where(x => x.Score > 0)
            .OrderByDescending(x => x.Score)
            .ThenBy(x => x.Point.ChunkId, StringComparer.Ordinal)
            .Take(query.TopK)
            .Select(x => ToChunk(x.Point, x.Score))
            .ToList();

        return Task.FromResult<IReadOnlyList<KnowledgeChunk>>(ranked);
    }

    /// <summary>What an <em>unfiltered</em> search would have returned — the counterfactual §4 measured.</summary>
    /// <remarks>
    /// Deliberately not reachable through <see cref="IKnowledgeSearch"/>: <see cref="SemanticQuery"/>
    /// cannot express an unfiltered query. This exists so a test can show what the filter is
    /// buying rather than only that it was applied.
    /// </remarks>
    public IReadOnlyList<KnowledgeChunk> UnfilteredForTestingOnly(
        string text, KnowledgeCollection collection, int topK = SemanticQuery.DefaultTopK)
    {
        var terms = Tokenize(text);

        return
        [
            .. _points
                .Where(p => p.Routing.Contains(collection))
                .Select(p => (Point: p, Score: Overlap(terms, p)))
                .Where(x => x.Score > 0)
                .OrderByDescending(x => x.Score)
                .ThenBy(x => x.Point.ChunkId, StringComparer.Ordinal)
                .Take(topK)
                .Select(x => ToChunk(x.Point, x.Score)),
        ];
    }

    private static KnowledgeChunk ToChunk(CorpusPoint p, float score) => new(
        p.ChunkId, p.Source, p.Title, p.Text, score, CorpusVersion,
        p.CveId, p.CweId, CapecIds: null, p.TechniqueId);

    private static float Overlap(HashSet<string> terms, CorpusPoint point)
    {
        var text = Tokenize($"{point.Title} {point.Text}");
        text.IntersectWith(terms);
        return text.Count;
    }

    private static HashSet<string> Tokenize(string text) =>
        [.. text.Split([' ', ',', '.', '(', ')', '—', '-', ':', '"', '\''],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(t => t.ToLowerInvariant())
            .Where(t => t.Length > 2)];

    private static readonly KnowledgeCollection[] Both =
        [KnowledgeCollection.Offense, KnowledgeCollection.Defense];

    private static readonly KnowledgeCollection[] OffenseOnly = [KnowledgeCollection.Offense];
    private static readonly KnowledgeCollection[] DefenseOnly = [KnowledgeCollection.Defense];

    private static IEnumerable<CorpusPoint> Build()
    {
        // ---- the CWE-502 weakness definition: two chunks, the ones an exact lookup wants -----
        yield return new CorpusPoint(
            "cwe-502", KnowledgeSource.Cwe, KnowledgeContentType.Description, Both,
            "CWE-502: Deserialization of Untrusted Data",
            "The application deserializes untrusted data without sufficiently verifying that the "
            + "resulting data will be valid, letting an attacker control the type that is constructed.",
            CweId: "CWE-502");

        yield return new CorpusPoint(
            "cwe-502-mitigations", KnowledgeSource.Cwe, KnowledgeContentType.Mitigation, DefenseOnly,
            "CWE-502: Potential Mitigations",
            "Do not deserialize untrusted input. Where unavoidable, bind to an allow-list of "
            + "expected types and never resolve a type from the payload. Remediate by validating "
            + "before deserialization.",
            CweId: "CWE-502");

        // ---- twenty NVD chunks merely TAGGED with CWE-502 ------------------------------------
        // These are what cwe_id=CWE-502 returns when the source condition is dropped. They are
        // written to score well on remediation wording so they also reproduce the drowning.
        for (var i = 1; i <= 20; i++)
        {
            yield return new CorpusPoint(
                $"nvd-cve-2023-{1000 + i}", KnowledgeSource.Nvd, KnowledgeContentType.Description, Both,
                $"CVE-2023-{1000 + i}",
                "A deserialization of untrusted data vulnerability. Remediate by upgrading; "
                + "unsafe deserialization allows remote code execution in the affected product.",
                CveId: $"CVE-2023-{1000 + i}", CweId: "CWE-502");
        }

        // ---- the one CVE that IS in the corpus ------------------------------------------------
        yield return new CorpusPoint(
            "nvd-cve-2024-21907", KnowledgeSource.Nvd, KnowledgeContentType.Description, Both,
            "CVE-2024-21907",
            "Improper handling of exceptional conditions in Newtonsoft.Json allows a crafted "
            + "payload to cause denial of service.",
            CveId: "CVE-2024-21907", CweId: "CWE-755");

        // ---- CWE-284, the infra weakness with no CVE ------------------------------------------
        yield return new CorpusPoint(
            "cwe-284", KnowledgeSource.Cwe, KnowledgeContentType.Description, Both,
            "CWE-284: Improper Access Control",
            "The product does not restrict or incorrectly restricts access to a resource from an "
            + "unauthorized actor.",
            CweId: "CWE-284");

        // ---- offense: techniques and attack patterns -------------------------------------------
        yield return new CorpusPoint(
            "attack-t1078", KnowledgeSource.Attack, KnowledgeContentType.Description, OffenseOnly,
            "T1078: Valid Accounts",
            "Adversaries obtain and abuse credentials of existing accounts. An over-permissive "
            + "role lets a compromised workload reach storage its function never required.",
            TechniqueId: "T1078");

        yield return new CorpusPoint(
            "capec-capec-586", KnowledgeSource.Capec, KnowledgeContentType.Description, OffenseOnly,
            "CAPEC-586: Object Injection",
            "An adversary crafts a serialized object that, when deserialized, constructs a type "
            + "with side effects, turning a data channel into code execution.");

        // ---- defense: detections, and the OWASP guidance an unfiltered query buries -------------
        yield return new CorpusPoint(
            "attack-t1078-detection", KnowledgeSource.Attack, KnowledgeContentType.Detection, DefenseOnly,
            "T1078: Detection",
            "Monitor for account usage that deviates from expected behaviour, such as a workload "
            + "role reading storage it has never read before.",
            TechniqueId: "T1078");

        yield return new CorpusPoint(
            "owasp-2021-a01-s00", KnowledgeSource.Owasp, KnowledgeContentType.Guidance, DefenseOnly,
            "A01:2021 Broken Access Control",
            "Enforce least privilege and deny by default. Scope resource ARNs; a wildcard action "
            + "is an unbounded blast radius. Remediate access control at the policy, not the caller.");

        yield return new CorpusPoint(
            "owasp-2021-a08-s00", KnowledgeSource.Owasp, KnowledgeContentType.Guidance, DefenseOnly,
            "A08:2021 Software and Data Integrity Failures",
            "Do not deserialize untrusted input. Remediate by using integrity checks such as "
            + "digital signatures on serialized objects.");
    }
}

/// <summary>
/// A deterministic embedder. Produces dense always and sparse only when told to, so the
/// dense-only degradation path is exercised as a configuration rather than as a mock.
/// </summary>
/// <remarks>
/// The vectors are meaningless numbers, and that is fine — <see cref="FakeCorpus"/> ranks on
/// token overlap. What matters is that the service passes <em>something</em> with the right
/// sparse-or-not shape, because that is what decides hybrid versus semantic.
/// </remarks>
internal sealed class FakeEmbedder(bool withSparse = true) : IQueryEmbedder
{
    public string Model => "BAAI/bge-m3";
    public string Revision => "5617a9f61b028005a4858fdac845db406aefb181";
    public int DenseDimensions => 1024;

    /// <summary>Configurable, so the no-model deployment is exercised as a configuration.</summary>
    public bool IsAvailable { get; init; } = true;

    public int Calls { get; private set; }

    public Task<QueryVectors> EmbedAsync(string text, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(text);
        Calls++;

        var dense = new float[DenseDimensions];
        for (var i = 0; i < dense.Length; i++) dense[i] = (text.Length + i) % 7 / 7f;

        var sparse = withSparse
            ? SparseQueryVector.Create([1u, 2u, 3u], [0.5f, 0.25f, 0.125f])
            : null;

        return Task.FromResult(new QueryVectors(dense, sparse));
    }
}
