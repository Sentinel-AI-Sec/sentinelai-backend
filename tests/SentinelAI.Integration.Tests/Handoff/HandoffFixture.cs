using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Debate;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Reporting;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Application.Features.Scan.ThinSlice;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;
using SentinelAI.Infrastructure.Knowledge;

namespace SentinelAI.Integration.Tests.Handoff;

/// <summary>
/// Shared scaffolding for the SEC-47 stage-boundary handoff suite: one seeded finding, the real
/// stage components, and the two test doubles for the genuine externals (Qdrant, the LLM).
/// </summary>
/// <remarks>
/// <para>
/// SEC-47's job is to make the silent island bug loud. The bug is a node-id disagreement between
/// two stages — one writes <c>iam_role:order</c>, the next looks up <c>role:order</c> — that
/// throws nothing and produces zero exploit chains. Each class here pins one boundary so that a
/// drift breaks a named test on the PR that caused it, not the demo three sprints later.
/// </para>
/// <para>
/// The components under test are the real ones. The only things faked are the two genuine
/// externals: the Qdrant-backed retriever (a capturing/canned <see cref="IKnowledgeRetriever"/>)
/// and the model provider (the offline <c>Scripted</c> provider — no network, no key, no spend).
/// Mocking the boundary itself would defeat the point of an integration test.
/// </para>
/// </remarks>
internal static class HandoffFixture
{
    public static readonly Guid Tenant = Guid.NewGuid();
    public static readonly Guid Job = Guid.NewGuid();

    /// <summary>
    /// The SEC-45 flagship finding: unsafe deserialization in OrderService, CWE-502, severity 4.
    /// Its node reference is built through <see cref="NodeId"/> — never by concatenation — so it
    /// is canonical by construction and the graph seam can be trusted to join it.
    /// </summary>
    public static Finding SeededFinding() => new()
    {
        Id = Guid.CreateVersion7(),
        TenantId = Tenant,
        ScanJobId = Job,
        SourceTool = ScannerNames.Roslyn,
        CheckId = "SCS0028",
        Layer = Layer.Code,
        Severity = 4,
        CweId = "CWE-502",
        CveId = null,
        NodeRef = NodeId.Code("OrderService"),
        Message = "Unsafe deserialization in OrderService",
    };

    /// <summary>A low-severity finding on the same node, for the is-hot handoff.</summary>
    public static Finding LowSeverityFindingOnSameNode() => new()
    {
        Id = Guid.CreateVersion7(),
        TenantId = Tenant,
        ScanJobId = Job,
        SourceTool = ScannerNames.Roslyn,
        CheckId = "SCS0000",
        Layer = Layer.Code,
        Severity = 1,
        CweId = "CWE-502",
        NodeRef = NodeId.Code("OrderService"),
        Message = "A low-severity note on the same code symbol.",
    };

    /// <summary>
    /// The real Red/Blue/Reporter debate engine wired to the offline <c>Scripted</c> provider, so
    /// the agent handoffs run for real without a network call or a credential.
    /// </summary>
    public static DebateEngine RealDebateOffline()
    {
        var providerOptions = new ModelProviderOptions { Provider = ModelProvider.Scripted };
        return new DebateEngine(
            new ChatClientFactory(providerOptions),
            Options.Create(new DebateOptions { MaxRounds = 2 }));
    }

    /// <summary>
    /// The real pipeline (graph → retrieve → brief → debate → report). Callers inject the debate
    /// and/or retriever double they need for the boundary under test; everything else is real.
    /// </summary>
    public static ThinSlicePipeline BuildPipeline(
        IDebateEngine? debate = null, IKnowledgeRetriever? retriever = null) =>
        new(new GraphSeeder(),
            new RetrievalQueryBuilder(),
            retriever ?? new SeedKnowledgeRetriever(NullLogger<SeedKnowledgeRetriever>.Instance),
            new ScanBriefRenderer(),
            debate ?? RealDebateOffline(),
            new ReportBuilder(),
            NullLogger<ThinSlicePipeline>.Instance);
}

/// <summary>Records every query the pipeline builds, so a boundary test can assert its shape.</summary>
internal sealed class CapturingRetriever(params string[] canned) : IKnowledgeRetriever
{
    public List<(string Query, string Collection)> Calls { get; } = [];

    public Task<IReadOnlyList<string>> RetrieveAsync(string query, string collection, CancellationToken ct = default)
    {
        Calls.Add((query, collection));
        IReadOnlyList<string> result = canned.Length > 0 ? canned : ["[CWE-502] canned knowledge chunk"];
        return Task.FromResult(result);
    }
}

/// <summary>
/// Captures the <see cref="ScanBrief"/> handed to the debate — the object Red actually receives —
/// and returns a fixed audit so the retrieval→Red boundary can be asserted without running a debate.
/// </summary>
internal sealed class CapturingDebate : IDebateEngine
{
    public ScanBrief? Received { get; private set; }

    public Task<DraftAudit> RunAsync(ScanBrief brief, CancellationToken ct = default)
    {
        Received = brief;
        return Task.FromResult(new DraftAudit
        {
            Summary = "captured",
            Transcript = [new DebateTurn { Role = AgentRole.Red, Round = 1, Content = "noted" }],
            Rounds = 1,
            TerminatedByTurnCap = false,
            Converged = true,
            WeakestJoin = Confidence.Unresolved,
        });
    }
}

/// <summary>A debate that returns a caller-supplied audit, for the Reporter→PR boundary.</summary>
internal sealed class StubDebate(DraftAudit audit) : IDebateEngine
{
    public Task<DraftAudit> RunAsync(ScanBrief brief, CancellationToken ct = default) => Task.FromResult(audit);
}
