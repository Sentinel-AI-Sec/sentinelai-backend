using SentinelAI.Application.Features.Scan.ThinSlice;

namespace SentinelAI.Integration.Tests.Handoff;

/// <summary>
/// Boundary 2 — Graph → Retrieval. The query builder must hand the retriever a query keyed on the
/// finding's linking identifier (CWE/CVE), not on scanner boilerplate.
/// </summary>
/// <remarks>
/// The corpus is matched exactly on the CWE/CVE id; a query that led with a tool name, a rule id,
/// a file path or a severity word would retrieve the wrong knowledge or none. This drives the real
/// <see cref="ThinSlicePipeline"/> and captures the query it emits through a fake retriever — Qdrant
/// is the one genuine external, so it is the only thing stubbed.
/// </remarks>
public class GraphToRetrievalHandoffTests
{
    [Fact]
    public async Task The_query_leads_with_the_findings_cwe_and_omits_scanner_boilerplate()
    {
        var retriever = new CapturingRetriever();
        var pipeline = HandoffFixture.BuildPipeline(debate: new CapturingDebate(), retriever: retriever);

        await pipeline.RunAsync([HandoffFixture.SeededFinding()], HandoffFixture.Tenant, HandoffFixture.Job);

        // One call per retrieving agent since SEC-23 — Red against offense, Blue against defense.
        Assert.Equal(2, retriever.Calls.Count);

        var (query, _) = retriever.Calls[0];

        // Keyed on the identifier the corpus can match exactly.
        Assert.StartsWith("CWE-502", query, StringComparison.Ordinal);
        Assert.Equal(["offense", "defense"], retriever.Calls.Select(c => c.Collection));

        // None of the scanner's structural boilerplate leaks into the query: not the tool name,
        // not the rule/check id, not the SARIF severity word, not a source path.
        Assert.DoesNotContain("roslyn", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SCS0028", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("warning", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(".cs", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("file:///", query, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_finding_with_no_linking_key_produces_no_retrieval_query()
    {
        // Nothing the corpus can be keyed on means nothing to retrieve — the stage must skip it,
        // not send a boilerplate query that matches noise. (This is the gap SEC-15's table closes.)
        var finding = HandoffFixture.SeededFinding();
        finding.CweId = null;
        finding.CveId = null;

        var retriever = new CapturingRetriever();
        var pipeline = HandoffFixture.BuildPipeline(debate: new CapturingDebate(), retriever: retriever);

        await pipeline.RunAsync([finding], HandoffFixture.Tenant, HandoffFixture.Job);

        Assert.Empty(retriever.Calls);
    }
}
