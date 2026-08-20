using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Integration.Tests.Regression;

/// <summary>One point in the regression corpus — the payload fields SEC-22 filters or reads.</summary>
internal sealed record RegressionPoint(
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
/// A small deterministic corpus, shaped so that the SEC-22 decision tree takes every arm over
/// the golden bundle's findings.
/// </summary>
/// <remarks>
/// <para>
/// <b>What it is for.</b> SEC-49 asserts that all three retrieval modes fire on the fixture.
/// That is a claim about the tree branching, not about ranking quality, so scoring here is
/// deterministic token overlap rather than an embedding. What it does reproduce faithfully is
/// the <em>filtering</em>: collection routing, the mandatory <c>source</c> condition, and
/// <c>content_type</c> — because those are what decide which arm answers, and a fake more
/// permissive than Qdrant would let a broken filter pass.
/// </para>
/// <para>
/// <b>The coverage is deliberately uneven, and that is the design.</b> CWE-502 and CWE-284 have
/// weakness definitions here, so findings carrying them are answered by the exact arm.
/// CVE-2024-21907 and CWE-778 are deliberately absent, so their findings fall through to the
/// meaning-based arms — which is how the semantic and hybrid modes get exercised at all. A
/// corpus that answered everything exactly would leave two thirds of SEC-22 unmeasured while
/// reporting 100% grounding coverage, which is the exact failure
/// <see cref="RetrievalEvaluation"/> exists to make visible.
/// </para>
/// <para>
/// This is a test corpus and is never the live one. The live corpus is proven by
/// <c>LiveCorpusSmokeTests</c>, which builds its own container and skips when none is reachable.
/// </para>
/// </remarks>
internal sealed class RegressionCorpus : IKnowledgeSearch
{
    public const string CorpusVersion = "regression-2026-08-19";

    private static readonly KnowledgeCollection[] Both =
        [KnowledgeCollection.Offense, KnowledgeCollection.Defense];

    private static readonly KnowledgeCollection[] OffenseOnly = [KnowledgeCollection.Offense];
    private static readonly KnowledgeCollection[] DefenseOnly = [KnowledgeCollection.Defense];

    /// <summary>Every exact lookup this corpus was asked, so a test can assert the filter shape.</summary>
    public List<ExactLookup> ExactLookups { get; } = [];

    /// <summary>Every semantic query, paired with the vectors it was given.</summary>
    public List<(SemanticQuery Query, QueryVectors Vectors)> Searches { get; } = [];

    private readonly List<RegressionPoint> _points = [.. Build()];

    public Task<IReadOnlyList<KnowledgeChunk>> ExactAsync(ExactLookup lookup, CancellationToken ct = default)
    {
        ExactLookups.Add(lookup);

        var matches = _points
            .Where(p => p.Routing.Contains(lookup.Collection))
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

    private static KnowledgeChunk ToChunk(RegressionPoint p, float score) => new(
        p.ChunkId, p.Source, p.Title, p.Text, score, CorpusVersion,
        p.CveId, p.CweId, CapecIds: null, p.TechniqueId, Status: null);

    private static float Overlap(HashSet<string> terms, RegressionPoint point)
    {
        var text = Tokenize($"{point.Title} {point.Text}");
        text.IntersectWith(terms);
        return text.Count;
    }

    private static HashSet<string> Tokenize(string text) =>
        [.. text.Split([' ', ',', '.', '(', ')', '—', '-', ':', '"', '\'', '/', '\n'],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(t => t.ToLowerInvariant())
            .Where(t => t.Length > 2)];

    /// <summary>
    /// The corpus itself. Deliberately broad in wording so token overlap finds something for
    /// any of the golden bundle's queries; deliberately narrow in <em>identifiers</em> so the
    /// exact arm answers some findings and not others.
    /// </summary>
    private static IEnumerable<RegressionPoint> Build()
    {
        // ---- weakness definitions: the exact arm's answers ---------------------------------
        yield return new RegressionPoint(
            "cwe-502", KnowledgeSource.Cwe, KnowledgeContentType.Description, Both,
            "CWE-502: Deserialization of Untrusted Data",
            "The application deserializes untrusted data without sufficiently verifying that the "
            + "resulting data will be valid, letting an attacker control the type that is "
            + "constructed and reach remote code execution.",
            CweId: "CWE-502");

        yield return new RegressionPoint(
            "cwe-502-mitigations", KnowledgeSource.Cwe, KnowledgeContentType.Mitigation, DefenseOnly,
            "CWE-502: Potential Mitigations",
            "Do not deserialize untrusted input. Where unavoidable, bind to an allow-list of "
            + "expected types and never resolve a type from the payload; validate before "
            + "deserialization and upgrade the affected package.",
            CweId: "CWE-502");

        yield return new RegressionPoint(
            "cwe-284", KnowledgeSource.Cwe, KnowledgeContentType.Description, Both,
            "CWE-284: Improper Access Control",
            "The product does not restrict or incorrectly restricts access to a resource from an "
            + "unauthorized actor. Wildcard IAM policy statements granting every action on every "
            + "resource are a common instance.",
            CweId: "CWE-284");

        yield return new RegressionPoint(
            "cwe-284-mitigations", KnowledgeSource.Cwe, KnowledgeContentType.Mitigation, DefenseOnly,
            "CWE-284: Potential Mitigations",
            "Grant least privilege. Replace wildcard action and resource statements in an IAM "
            + "policy with the specific operations and bucket ARNs the workload needs, and review "
            + "role trust policies for over-broad principals.",
            CweId: "CWE-284");

        // ---- offense: techniques and patterns, which is what the semantic arm reaches -------
        yield return new RegressionPoint(
            "attack-t1190", KnowledgeSource.Attack, KnowledgeContentType.Description, OffenseOnly,
            "T1190: Exploit Public-Facing Application",
            "Adversaries exploit a weakness in an internet-facing host to gain initial access, "
            + "including unsafe deserialization of untrusted data in a web application and "
            + "vulnerable third-party packages reached through request handling.",
            TechniqueId: "T1190");

        yield return new RegressionPoint(
            "attack-t1078-004", KnowledgeSource.Attack, KnowledgeContentType.Description, OffenseOnly,
            "T1078.004: Valid Accounts — Cloud Accounts",
            "Adversaries obtain and abuse cloud credentials attached to a compute role to access "
            + "storage. An over-permissioned task role with a wildcard policy lets an attacker "
            + "read every bucket in the account, including customer data.",
            TechniqueId: "T1078.004");

        yield return new RegressionPoint(
            "capec-586", KnowledgeSource.Capec, KnowledgeContentType.Description, OffenseOnly,
            "CAPEC-586: Object Injection",
            "An adversary supplies a crafted serialized object so that deserialization "
            + "instantiates a type of the attacker's choosing, executing code as the "
            + "application. Logging misconfiguration hides the access that follows.",
            TechniqueId: null);

        yield return new RegressionPoint(
            "capec-122", KnowledgeSource.Capec, KnowledgeContentType.Description, OffenseOnly,
            "CAPEC-122: Privilege Abuse",
            "An adversary uses legitimate but excessive permissions granted to a role or task to "
            + "read or modify resources the workload never needed, such as an S3 bucket holding "
            + "customer data, without any access logging to reveal it.");

        // ---- defense: mitigations for the findings whose CWE is deliberately absent ---------
        yield return new RegressionPoint(
            "capec-586-mitigations", KnowledgeSource.Capec, KnowledgeContentType.Mitigation, DefenseOnly,
            "CAPEC-586: Mitigations",
            "Upgrade the vulnerable package to a fixed version and reject serialized payloads "
            + "from untrusted callers. Where a serializer must accept them, constrain the type "
            + "resolver to an explicit allow-list.");

        yield return new RegressionPoint(
            "owasp-logging", KnowledgeSource.Owasp, KnowledgeContentType.Guidance, DefenseOnly,
            "Security Logging and Monitoring Failures",
            "Enable access logging on storage buckets and ship the logs somewhere they are "
            + "reviewed. Without server access logging, unauthorized reads of a bucket leave no "
            + "record and a breach is discovered by someone else.");

        yield return new RegressionPoint(
            "attack-m1013", KnowledgeSource.Attack, KnowledgeContentType.Mitigation, DefenseOnly,
            "M1013: Application Developer Guidance",
            "Guide developers away from unsafe deserialization of untrusted data and toward "
            + "upgrading vulnerable dependencies promptly; enable logging so exploitation of a "
            + "public-facing application is visible.");
    }
}

/// <summary>
/// A deterministic stand-in for the embedding service, in the two configurations that decide
/// whether the tree reports <see cref="RetrievalMode.Semantic"/> or
/// <see cref="RetrievalMode.Hybrid"/>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Which of the two fires is a property of the deployment, not of the finding.</b> A model
/// with no lexical half can never produce a sparse vector, so hybrid never fires there however
/// many findings are scanned — which is exactly why <see cref="RetrievalEvaluation"/>'s own
/// remarks say proving "all three modes fire" means concatenating results from more than one
/// run. The harness runs retrieval twice, once with each configuration, and evaluates the
/// union. Faking one embedder that returns sparse for some queries and not others would prove
/// the modes fire in a configuration that does not exist.
/// </para>
/// <para>
/// The vectors are not meaningful and are not meant to be: <see cref="RegressionCorpus"/> ranks
/// by token overlap and never looks at them. What matters is only whether a sparse half is
/// present, because that is the one bit the decision tree reads.
/// </para>
/// </remarks>
internal sealed class RegressionEmbedder(bool sparse) : IQueryEmbedder
{
    /// <summary>The corpus in use was indexed with this model — see <c>PIPELINE_A_CONTEXT.md</c> §5.</summary>
    public string Model => "BAAI/bge-m3";

    public string Revision => "5617a9f61b028005a4858fdac845db406aefb181";

    public int DenseDimensions => 1024;

    public bool IsAvailable => true;

    /// <summary>Dense-only: the deployment whose model has no lexical half.</summary>
    public static RegressionEmbedder DenseOnly() => new(sparse: false);

    /// <summary>Dense plus sparse: the deployment where RRF fusion is available.</summary>
    public static RegressionEmbedder Hybrid() => new(sparse: true);

    public Task<QueryVectors> EmbedAsync(string text, CancellationToken ct = default)
    {
        // Derived from the text so two different queries do not produce the same vector — not
        // because the corpus reads them, but because a vector that ignored its input would make
        // a caller passing the wrong text impossible to notice here.
        var seed = (uint)(text?.GetHashCode(StringComparison.Ordinal) ?? 0);
        var dense = Enumerable.Range(0, DenseDimensions).Select(i => (seed + (uint)i) % 97 / 97f).ToArray();

        var vectors = sparse
            ? new QueryVectors(dense, SparseQueryVector.Create([seed % 5000, seed % 7919], [0.7f, 0.3f]))
            : new QueryVectors(dense, Sparse: null);

        return Task.FromResult(vectors);
    }
}
