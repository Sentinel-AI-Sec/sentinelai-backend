using System.Text;

namespace SentinelAI.Integration.Tests.Regression;

/// <summary>
/// The stages SEC-49's harness can attribute a regression to.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is not <c>ScanPipelineStage</c>, and the difference is the whole point of SEC-49.</b>
/// That enum has three values because the runner can only place three <c>try</c> boundaries —
/// retrieve, debate and report are one call into <c>ThinSlicePipeline</c> and therefore one
/// catch. The harness is not bound by that: it drives the flow from outside, one HTTP call and
/// one observation at a time, so it can say "the graph built but no chain crossed the code
/// layer" where the runner could only say "Graph".
/// </para>
/// <para>
/// <b>Ordered, and the order is load-bearing.</b> Every stage consumes the previous one's
/// output, so the <em>first</em> stage that fails is the one to look at and everything after it
/// is a consequence. <see cref="FullFlowRun.Diagnosis"/> prints them in this order for exactly
/// that reason: a report that lists eight failures tells you nothing, and a report that names
/// the first one tells you where to start.
/// </para>
/// </remarks>
public enum FullFlowStage
{
    /// <summary>The bundle was accepted by <c>POST /v1/scans</c> and stored (SEC-13).</summary>
    Ingest,

    /// <summary>The scanners' files became one unified, redacted finding set (SEC-14/15/16, SEC-33).</summary>
    Normalize,

    /// <summary>The four seams built one connected, attack-oriented resource graph (SEC-17/18/19).</summary>
    Graph,

    /// <summary>The bounded traversal found the three-layer chain over that graph (SEC-20).</summary>
    Chain,

    /// <summary>The decision tree grounded the findings, and every arm of it answered (SEC-22/25).</summary>
    Retrieval,

    /// <summary>Red, Blue and the Reporter ran and the debate terminated (SEC-26/27/29).</summary>
    Debate,

    /// <summary>An adjudicated, cited report was produced and retained (SEC-45, SEC-35).</summary>
    Report,

    /// <summary>The read API serves what the pipeline wrote, in the shape the UI expects (SEC-40).</summary>
    ReadBack,
}

/// <summary>What one stage of a harness run observed.</summary>
/// <param name="Stage">Which stage.</param>
/// <param name="Succeeded">False when the stage did not produce what the next one needs.</param>
/// <param name="Detail">
/// One line of evidence — the counts, keys or status the stage actually produced. Present on
/// success as well as failure, because the number a passing stage produced is what a reader
/// compares against when a later one fails.
/// </param>
public sealed record FullFlowObservation(FullFlowStage Stage, bool Succeeded, string Detail);

/// <summary>
/// One end-to-end run of the fixture through the deployed API surface, with a per-stage record
/// of what happened (SEC-49).
/// </summary>
/// <remarks>
/// The run stops at its first failing stage rather than pressing on. Continuing would produce a
/// second, third and fourth failure that are all restatements of the first — "the debate found
/// no chains" after the graph stage built no graph is not new information, and a harness whose
/// output has to be read backwards to find the real cause is one nobody reads.
/// </remarks>
public sealed record FullFlowRun
{
    public required Guid ScanJobId { get; init; }

    public required IReadOnlyList<FullFlowObservation> Observations { get; init; }

    /// <summary>The findings the normalize stage produced, by layer name.</summary>
    public IReadOnlyDictionary<string, int> FindingsByLayer { get; init; } =
        new Dictionary<string, int>(StringComparer.Ordinal);

    /// <summary>Every candidate chain the graph stage found, as its node-key path.</summary>
    public IReadOnlyList<IReadOnlyList<string>> ChainPaths { get; init; } = [];

    /// <summary>Every persisted edge, as <c>from -relation-> to</c>, with its orientation flag.</summary>
    public IReadOnlyList<(string From, string Relation, string To, bool Oriented)> Edges { get; init; } = [];

    /// <summary>Which retrieval arms answered, over the union of the harness's retrieval runs.</summary>
    public IReadOnlyList<string> RetrievalModesThatFired { get; init; } = [];

    /// <summary>The chunk ids the report cited. Empty means an audit with nothing behind it.</summary>
    public IReadOnlyList<string> CitedChunkIds { get; init; } = [];

    /// <summary>The chain paths the retained report leads with, read back through the read API.</summary>
    public IReadOnlyList<IReadOnlyList<string>> ReportedChainPaths { get; init; } = [];

    /// <summary>The first stage that did not produce what the next one needed, or null.</summary>
    public FullFlowStage? BrokenStage =>
        Observations.FirstOrDefault(o => !o.Succeeded)?.Stage;

    public bool Succeeded => BrokenStage is null;

    /// <summary>
    /// The whole run as a readable stage table, with the broken stage called out.
    /// </summary>
    /// <remarks>
    /// Attached to every assertion message in <see cref="FullFlowRegressionTests"/>, so a CI
    /// failure carries the pinpoint with it rather than requiring someone to reproduce the run
    /// locally to find out which stage went wrong. That is SEC-49's second acceptance criterion
    /// ("a broken stage is pinpointed"), and it is only satisfied if the pinpoint reaches the
    /// person reading the log.
    /// </remarks>
    public string Diagnosis
    {
        get
        {
            var text = new StringBuilder();
            text.AppendLine();
            text.AppendLine($"SEC-49 full-flow run for scan job {ScanJobId}");

            text.AppendLine(BrokenStage is { } broken
                ? $"  BROKEN AT: {broken}"
                : "  every stage produced what the next one needed");

            text.AppendLine();

            foreach (var observation in Observations)
            {
                var marker = observation.Succeeded ? "ok  " : "FAIL";
                text.AppendLine($"  [{marker}] {observation.Stage,-9} {observation.Detail}");
            }

            // Stages the run never got to. Named explicitly so "not measured" and "measured and
            // fine" cannot be confused by their shared absence from the failure list.
            var reached = Observations.Select(o => o.Stage).ToHashSet();
            var unreached = Enum.GetValues<FullFlowStage>().Where(s => !reached.Contains(s)).ToList();

            if (unreached.Count > 0)
                text.AppendLine($"  not reached: {string.Join(", ", unreached)}");

            return text.ToString();
        }
    }
}
