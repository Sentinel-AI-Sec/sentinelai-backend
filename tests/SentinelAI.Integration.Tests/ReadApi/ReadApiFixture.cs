using System.Net.Http.Headers;
using System.Text.Json;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.ReadApi;

/// <summary>
/// Shared setup for the read API tests (SEC-40): one seeded scan with findings, a graph and a
/// chain, plus clients holding whatever scopes a test needs.
/// </summary>
internal sealed class ReadApiFixture(ScanApiFactory factory)
{
    public Guid TenantId { get; } = Guid.NewGuid();
    public Guid ScanJobId { get; private set; }

    /// <summary>
    /// The project the seeded scan belongs to.
    /// </summary>
    /// <remarks>
    /// Exposed because a test cannot read it back out of the seeding context: <c>SeedAsync</c>
    /// writes past the tenant query filter, but that filter still shapes reads and the seeding
    /// scope resolves no tenant.
    /// </remarks>
    public Guid ProjectId { get; private set; }
    public Guid ReportId { get; private set; }

    /// <summary>Node keys seeded into the graph, in the order they were written.</summary>
    public string[] NodeKeys { get; } = ["pkg:newtonsoft.json:9.0.1", "code:orderservice.deserialize", "s3:customer-data"];

    /// <summary>A client carrying the given scopes for this fixture's tenant.</summary>
    public HttpClient Client(params string[] scopes)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", TestJwt.Create(TenantId, userId: Guid.NewGuid(), role: Roles.Analyst, scopes: scopes));
        return client;
    }

    /// <summary>A client for a <em>different</em> tenant — the read-leak probe.</summary>
    public HttpClient ForeignClient(params string[] scopes)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", TestJwt.Create(Guid.NewGuid(), userId: Guid.NewGuid(), role: Roles.Analyst, scopes: scopes));
        return client;
    }

    public HttpClient AnonymousClient() => factory.CreateClient();

    /// <summary>
    /// Seeds one scan the way the graph stage leaves it: findings, nodes, an edge, a chain with
    /// hops, a bundle record and a retained report.
    /// </summary>
    public async Task SeedAsync()
    {
        var projectId = Guid.CreateVersion7();
        var jobId = Guid.CreateVersion7();
        var reportId = Guid.CreateVersion7();

        await factory.SeedAsync(db =>
        {
            db.Projects.Add(new Project
            {
                Id = projectId, TenantId = TenantId,
                RepoUrl = "https://example.test/repo", DefaultBranch = "main",
            });

            db.ScanJobs.Add(new ScanJob
            {
                Id = jobId, TenantId = TenantId, ProjectId = projectId,
                PrRef = "pr/1", CommitSha = "abc123", Status = ScanStatus.Completed,
                CorpusVersion = "2026-07-15", StartedAt = DateTime.UtcNow, Stage = ScanStage.Report,
            });

            db.ScanBundles.Add(new ScanBundle
            {
                Id = Guid.CreateVersion7(), TenantId = TenantId, ScanJobId = jobId,
                RunnerSecretScan = "passed", IngressRedactionApplied = true,
                ArtifactManifest = "[\"roslyn.sarif\"]", ScannerVersions = "{\"roslyn\":\"1.0\"}",
                ReceivedAt = DateTime.UtcNow, Sha256 = "deadbeef", SizeBytes = 4096,
                StorageLocator = "loc",
            });

            // Three findings spanning all three layers and a range of severities, so the layer
            // and min_severity filters have something to actually discriminate.
            db.Findings.AddRange(
                Finding(jobId, ScannerNames.Osv, Layer.Dep, 4, "CWE-502", NodeKeys[0]),
                Finding(jobId, ScannerNames.Roslyn, Layer.Code, 3, "CWE-502", NodeKeys[1]),
                Finding(jobId, ScannerNames.Checkov, Layer.Infra, 1, "CWE-284", NodeKeys[2]));

            var nodes = new[]
            {
                Node(jobId, NodeKeys[0], NodeType.Pkg, Layer.Dep, isHot: true),
                Node(jobId, NodeKeys[1], NodeType.Code, Layer.Code, isHot: true),
                Node(jobId, NodeKeys[2], NodeType.Resource, Layer.Infra, isHot: false),
            };
            db.GraphNodes.AddRange(nodes);

            var edge = new GraphEdge
            {
                Id = Guid.CreateVersion7(), TenantId = TenantId, ScanJobId = jobId,
                FromNodeId = nodes[0].Id, ToNodeId = nodes[1].Id,
                Relation = "used-by", Seam = Seam.DepCode,
                Confidence = Confidence.Inferred, OrientedAttackDir = true,
            };
            db.GraphEdges.Add(edge);

            var chain = new Chain
            {
                Id = Guid.CreateVersion7(), TenantId = TenantId, ScanJobId = jobId,
                HopCount = 2, Priority = 1, Status = ChainStatus.Candidate,
                // Weakest join anywhere in the chain — the edge above is only Inferred.
                MinConfidence = Confidence.Inferred,
            };
            db.Chains.Add(chain);

            db.ChainHops.Add(new ChainHop
            {
                Id = Guid.CreateVersion7(), TenantId = TenantId, ChainId = chain.Id,
                // blue_validated is derived from the verdict now (audit 42-A), so a fixture that
                // wants a validated hop states the verdict that makes it one.
                EdgeId = edge.Id, HopOrder = 1, TechniqueId = "T1190",
                BlueVerdict = HopVerdict.Confirmed,
            });

            var report = new Report
            {
                Id = reportId, TenantId = TenantId, ScanJobId = jobId,
                Framing = "draft_audit", Summary = "Draft audit for review.",
                Retained = true, CreatedAt = DateTime.UtcNow,
                CostCurrency = "USD", ModelCalls = 4, CostRated = true,
            };
            db.Reports.Add(report);

            db.Citations.Add(new Citation
            {
                Id = Guid.CreateVersion7(), TenantId = TenantId, ReportId = report.Id,
                KnowledgeId = "CWE-502", Source = "OWASP", Collection = "offense",
            });
        });

        ScanJobId = jobId;

        ProjectId = projectId;
        ReportId = reportId;
    }

    private Finding Finding(Guid jobId, string tool, Layer layer, int severity, string cwe, string nodeRef) => new()
    {
        Id = Guid.CreateVersion7(), TenantId = TenantId, ScanJobId = jobId,
        SourceTool = tool, Layer = layer, Severity = severity,
        CweId = cwe, NodeRef = nodeRef, Message = $"{tool} finding on {nodeRef}",
    };

    private GraphNode Node(Guid jobId, string key, NodeType type, Layer layer, bool isHot) => new()
    {
        Id = Guid.CreateVersion7(), TenantId = TenantId, ScanJobId = jobId,
        NodeKey = key, NodeType = type, Layer = layer, IsHot = isHot,
    };

    /// <summary>Reads a response body as JSON for assertions about the wire shape.</summary>
    public static async Task<JsonElement> JsonAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.Clone();
    }
}
