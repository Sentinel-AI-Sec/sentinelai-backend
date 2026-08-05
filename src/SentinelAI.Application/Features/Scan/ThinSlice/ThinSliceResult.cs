using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.ThinSlice;

/// <summary>
/// Everything the walking skeleton produced, one property per stage (SEC-45).
/// </summary>
/// <remarks>
/// It exposes each stage's output rather than only the final report, because the whole value of
/// the thin slice is proving the <em>seams</em> hold — and a test that can only see the report
/// cannot tell a graph that was built and used from one that was silently empty. When a stage
/// is deepened later, the shape it must keep producing is the one named here.
/// </remarks>
public sealed record ThinSliceResult
{
    /// <summary>Stage 1 — the unified findings that entered the pipe.</summary>
    public required IReadOnlyList<Finding> Findings { get; init; }

    /// <summary>Stage 2 — the nodes those findings decorate.</summary>
    public required IReadOnlyList<GraphNode> Nodes { get; init; }

    /// <summary>Stage 3 — knowledge chunks retrieved for the findings' linking keys.</summary>
    public required IReadOnlyList<string> Knowledge { get; init; }

    /// <summary>The brief handed to the debate: stage 2 and 3 rendered for the agents.</summary>
    public required ScanBrief Brief { get; init; }

    /// <summary>Stage 4 — the debate's adjudicated output.</summary>
    public required DraftAudit Audit { get; init; }

    /// <summary>Stage 5 — the persistable report, with citations.</summary>
    public required Report Report { get; init; }
}
