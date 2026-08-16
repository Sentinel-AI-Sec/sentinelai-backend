using System.Net;
using System.Text.Json;
using SentinelAI.Domain.Models;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.ReadApi;

/// <summary>
/// The wire contract of the read API (SEC-40), as fixed by <c>SentinelAI_API_Design_V2.1.md</c>.
/// </summary>
/// <remarks>
/// <para>
/// These assert on <b>raw JSON property names</b>, not on deserialized objects. That is the
/// point: deserializing into the same DTO the server serialized from would pass no matter what
/// the names were, and the names are the entire contract. The Angular screen (SEC-42) is being
/// built against this document in another repository, so a rename here breaks a teammate's work
/// with nothing in this solution failing.
/// </para>
/// <para>
/// Enums are asserted as words for the same reason — <c>"confidence": 2</c> is meaningless to a
/// renderer and changes meaning silently if a member is ever inserted into the enum.
/// </para>
/// </remarks>
public class ReadApiContractTests : IClassFixture<ScanApiFactory>
{
    private readonly ReadApiFixture _fixture;

    public ReadApiContractTests(ScanApiFactory factory)
    {
        _fixture = new ReadApiFixture(factory);
        _fixture.SeedAsync().GetAwaiter().GetResult();
    }

    private HttpClient Reader() => _fixture.Client(AuthScopes.ScanRead, AuthScopes.ReportRead);

    private async Task<JsonElement> GetAsync(string url)
    {
        var response = await Reader().GetAsync(url);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await ReadApiFixture.JsonAsync(response);
    }

    // ---- graph -------------------------------------------------------------------------

    [Fact]
    public async Task The_graph_returns_nodes_and_edges_with_confidence_tiers()
    {
        // SEC-40 acceptance box 1.
        var graph = await GetAsync($"/v1/scans/{_fixture.ScanJobId}/graph");

        Assert.Equal(_fixture.ScanJobId.ToString(), graph.GetProperty("scan_job_id").GetString());

        var nodes = graph.GetProperty("nodes").EnumerateArray().ToList();
        Assert.Equal(3, nodes.Count);

        var pkg = nodes.Single(n => n.GetProperty("node_key").GetString() == _fixture.NodeKeys[0]);
        Assert.Equal("pkg", pkg.GetProperty("type").GetString());
        Assert.Equal("dep", pkg.GetProperty("layer").GetString());
        Assert.True(pkg.GetProperty("is_hot").GetBoolean());

        var edge = Assert.Single(graph.GetProperty("edges").EnumerateArray().ToList());
        Assert.Equal("inferred", edge.GetProperty("confidence").GetString());
        Assert.Equal("dep-code", edge.GetProperty("seam").GetString());
        Assert.Equal("used-by", edge.GetProperty("relation").GetString());
    }

    [Fact]
    public async Task Graph_edges_address_nodes_by_key_not_by_row_id()
    {
        // A row id would force the screen to build a lookup table before it could draw
        // anything; the key is the canonical identity of the thing (SEC-03).
        var graph = await GetAsync($"/v1/scans/{_fixture.ScanJobId}/graph");
        var edge = graph.GetProperty("edges").EnumerateArray().First();

        Assert.Equal(_fixture.NodeKeys[0], edge.GetProperty("from").GetString());
        Assert.Equal(_fixture.NodeKeys[1], edge.GetProperty("to").GetString());
    }

    [Fact]
    public async Task An_iam_role_node_is_typed_role_while_its_key_keeps_the_historical_prefix()
    {
        // The type vocabulary and the node-key prefix are separate on purpose: keys are a
        // cross-repo identifier where Resource is historically spelled "s3".
        var graph = await GetAsync($"/v1/scans/{_fixture.ScanJobId}/graph");

        var bucket = graph.GetProperty("nodes").EnumerateArray()
            .Single(n => n.GetProperty("node_key").GetString() == _fixture.NodeKeys[2]);

        Assert.StartsWith("s3:", _fixture.NodeKeys[2], StringComparison.Ordinal);
        Assert.Equal("resource", bucket.GetProperty("type").GetString());
    }

    // ---- report ------------------------------------------------------------------------

    [Fact]
    public async Task The_report_carries_draft_audit_framing_and_per_chain_confidence()
    {
        // SEC-40 acceptance box 2. The framing is non-negotiable (AID-01 §7): this is
        // prioritized material for human review, never a verified verdict.
        var report = await GetAsync($"/v1/reports/{_fixture.ReportId}");

        Assert.Equal("draft_audit", report.GetProperty("framing").GetString());
        Assert.Equal(_fixture.ScanJobId.ToString(), report.GetProperty("scan_job_id").GetString());

        var chain = Assert.Single(report.GetProperty("chains").EnumerateArray().ToList());
        Assert.Equal("inferred", chain.GetProperty("min_confidence").GetString());
        Assert.Equal("candidate", chain.GetProperty("status").GetString());

        var citation = Assert.Single(report.GetProperty("citations").EnumerateArray().ToList());
        Assert.Equal("CWE-502", citation.GetProperty("knowledge_id").GetString());
        Assert.Equal("offense", citation.GetProperty("collection").GetString());
    }

    [Fact]
    public async Task The_report_reports_whether_its_cost_was_priced()
    {
        // A missing rate must not be indistinguishable from a free scan (SEC-31).
        var report = await GetAsync($"/v1/reports/{_fixture.ReportId}");
        var cost = report.GetProperty("cost");

        Assert.Equal("USD", cost.GetProperty("currency").GetString());
        Assert.Equal(4, cost.GetProperty("model_calls").GetInt32());
        Assert.True(cost.GetProperty("rated").GetBoolean());
    }

    // ---- findings ----------------------------------------------------------------------

    [Fact]
    public async Task Findings_come_back_as_a_page_with_snake_case_fields()
    {
        var page = await GetAsync($"/v1/scans/{_fixture.ScanJobId}/findings");

        Assert.Equal(3, page.GetProperty("items").GetArrayLength());
        Assert.True(page.TryGetProperty("next_cursor", out _));
        Assert.True(page.TryGetProperty("limit", out _));

        var finding = page.GetProperty("items").EnumerateArray().First();
        foreach (var field in new[] { "source_tool", "cwe_id", "cve_id", "node_ref", "severity", "layer" })
            Assert.True(finding.TryGetProperty(field, out _), $"missing '{field}'");
    }

    // ---- bundle ------------------------------------------------------------------------

    [Fact]
    public async Task The_bundle_endpoint_returns_provenance()
    {
        var bundle = await GetAsync($"/v1/scans/{_fixture.ScanJobId}/bundle");

        Assert.Equal("passed", bundle.GetProperty("runner_secret_scan").GetString());
        Assert.True(bundle.GetProperty("ingress_redaction_applied").GetBoolean());
        Assert.Equal("deadbeef", bundle.GetProperty("sha256").GetString());
        Assert.Equal(4096, bundle.GetProperty("size_bytes").GetInt64());

        // The provenance record outlives the bytes it describes (SEC-35), so the reader can
        // tell "never received" from "received and since deleted".
        Assert.False(bundle.GetProperty("bundle_purged").GetBoolean());
    }

    // ---- the envelope ------------------------------------------------------------------

    [Fact]
    public async Task Read_responses_are_bare_json_with_no_envelope()
    {
        // The older endpoints wrap payloads in {isSuccess, data, message}. The design document
        // the frontend has does not, and this is the difference a screen would break on.
        var graph = await GetAsync($"/v1/scans/{_fixture.ScanJobId}/graph");

        Assert.False(graph.TryGetProperty("data", out _));
        Assert.False(graph.TryGetProperty("isSuccess", out _));
        Assert.True(graph.TryGetProperty("nodes", out _));
    }
}
