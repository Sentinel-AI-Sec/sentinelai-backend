using System.Globalization;

namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>
/// SEC-25: what retrieval actually achieved over a set of findings.
/// </summary>
/// <remarks>
/// <para>
/// Two numbers, and they answer two different questions:
/// </para>
/// <list type="number">
/// <item><description>
/// <b>Grounding coverage</b> — what fraction of findings came back with at least one chunk. This
/// is the audit's honesty bound: an assertion about an ungrounded finding has nothing behind it,
/// so coverage is the ceiling on how much of a report can be cited.
/// </description></item>
/// <item><description>
/// <b>Per-mode fire rates</b> — how many findings each arm of the decision tree answered. A mode
/// that never fires is either dead code or a tree that stopped branching, and <em>neither shows
/// up in a coverage number</em>. That is the whole reason this type reports both: 100% coverage
/// with every finding answered by the exact arm means the semantic half of SEC-22 was never
/// exercised, and the first id-less finding in production would be the test.
/// </description></item>
/// </list>
///
/// <para><b>Findings, not chunks.</b></para>
/// <para>
/// A finding that retrieved ten chunks and one that retrieved one are both grounded. Averaging
/// chunk counts would let a handful of rich results hide a finding with nothing, which is exactly
/// the case the metric exists to surface. Coverage is a count of findings over findings.
/// </para>
///
/// <para><b>Why it is a type rather than a log line.</b></para>
/// <para>
/// <c>KnowledgeRetrievalService</c> logged these numbers from the day SEC-22 landed, and a log
/// line cannot be asserted on. This is the same arithmetic in a form a test can fail against, and
/// the service now logs <em>through</em> it so there is one definition of "coverage" rather than
/// two that drift.
/// </para>
/// </remarks>
public sealed record RetrievalEvaluation
{
    /// <summary>
    /// The arms that count as "a mode firing" — <see cref="RetrievalMode.None"/> is not one.
    /// </summary>
    /// <remarks>
    /// <c>None</c> is the ungrounded bucket, not a fourth way of answering. Counting it as a mode
    /// would make "all modes fired" satisfiable by a run that grounded nothing at all.
    /// </remarks>
    public static readonly IReadOnlyList<RetrievalMode> AnsweringModes =
        [RetrievalMode.ExactFilter, RetrievalMode.Semantic, RetrievalMode.Hybrid];

    private RetrievalEvaluation(IReadOnlyList<RetrievalResult> results)
    {
        Findings = results.Count;
        Grounded = results.Count(r => r.IsGrounded);
        FellBackToWeaknessClass = results.Count(r => r.FellBackToWeaknessClass);

        ByMode = Enum.GetValues<RetrievalMode>()
            .ToDictionary(mode => mode, mode => results.Count(r => r.Mode == mode));

        ModesThatDidNotFire = [.. AnsweringModes.Where(mode => ByMode[mode] == 0)];
    }

    /// <summary>Measures a set of results. Order is irrelevant; these are counts.</summary>
    /// <remarks>
    /// Takes results rather than findings so it can span several runs. That matters because
    /// <see cref="RetrievalMode.Hybrid"/> and <see cref="RetrievalMode.Semantic"/> are decided by
    /// the <em>embedder</em>, not by the finding — a deployment whose model has no lexical half
    /// can never fire hybrid — so "all three modes fire" is a claim about a configuration, and
    /// proving it means concatenating the results of more than one.
    /// </remarks>
    public static RetrievalEvaluation Of(IEnumerable<RetrievalResult> results)
    {
        ArgumentNullException.ThrowIfNull(results);

        return new RetrievalEvaluation([.. results]);
    }

    /// <summary>How many findings were put to the corpus.</summary>
    public int Findings { get; }

    /// <summary>How many came back with at least one chunk.</summary>
    public int Grounded { get; }

    /// <summary>How many findings each arm answered, including <see cref="RetrievalMode.None"/>.</summary>
    public IReadOnlyDictionary<RetrievalMode, int> ByMode { get; }

    /// <summary>
    /// How many were answered by the weakness class after their specific CVE missed.
    /// </summary>
    /// <remarks>
    /// Grounded, but less specifically than the finding deserved — <c>PIPELINE_A_CONTEXT.md</c> §7
    /// says the NVD slice is partial by design. Reported separately because it is invisible in
    /// coverage: these findings count as grounded, and they are, just not in the CVE.
    /// </remarks>
    public int FellBackToWeaknessClass { get; }

    /// <summary>The answering modes that never fired. Empty is the healthy state.</summary>
    public IReadOnlyList<RetrievalMode> ModesThatDidNotFire { get; }

    /// <summary>Findings that retrieved nothing at all.</summary>
    public int Ungrounded => Findings - Grounded;

    /// <summary>
    /// Grounding coverage as a fraction from 0 to 1. Zero findings scores 1.
    /// </summary>
    /// <remarks>
    /// An empty run is complete rather than failed: every one of its zero findings is grounded.
    /// Returning 0 would make a scan that found no problems look like a total retrieval failure,
    /// and a threshold check would fire on the cleanest possible result.
    /// </remarks>
    public double GroundingCoverage => Findings == 0 ? 1d : (double)Grounded / Findings;

    /// <summary>Coverage as a whole percentage, rounded down.</summary>
    /// <remarks>
    /// Truncated, not rounded: 199 grounded out of 200 is 99%, and a metric that reported it as
    /// 100% would erase the one finding the audit cannot support.
    /// </remarks>
    public int CoveragePercent => (int)Math.Floor(GroundingCoverage * 100);

    /// <summary>True when every finding retrieved something.</summary>
    public bool FullyGrounded => Grounded == Findings;

    /// <summary>
    /// True when all three answering modes fired at least once — SEC-25's acceptance criterion.
    /// </summary>
    public bool AllModesFired => ModesThatDidNotFire.Count == 0;

    /// <summary>Count for one mode, without a dictionary lookup at every call site.</summary>
    public int Count(RetrievalMode mode) => ByMode.GetValueOrDefault(mode);

    /// <summary>
    /// The one-line summary the service logs and a failing test prints.
    /// </summary>
    /// <remarks>
    /// Written to be readable in a log without a dashboard: the coverage fraction and the
    /// percentage both appear, because "48%" alone does not say whether that is 12 findings or
    /// 12,000, and the per-mode counts are what turn a regression from "coverage dropped" into
    /// "the semantic arm stopped firing".
    /// </remarks>
    public string Report()
    {
        var modes = string.Join(", ", AnsweringModes.Select(m => $"{Name(m)} {Count(m)}"));

        var line = string.Create(
            CultureInfo.InvariantCulture,
            $"grounding coverage {Grounded}/{Findings} ({CoveragePercent}%) — {modes}, "
            + $"ungrounded {Count(RetrievalMode.None)}; {FellBackToWeaknessClass} fell back to the "
            + $"weakness class");

        return ModesThatDidNotFire.Count == 0
            ? line
            : $"{line}. Modes that never fired: {string.Join(", ", ModesThatDidNotFire.Select(Name))}";
    }

    public override string ToString() => Report();

    private static string Name(RetrievalMode mode) => mode switch
    {
        RetrievalMode.ExactFilter => "exact",
        RetrievalMode.Semantic => "semantic",
        RetrievalMode.Hybrid => "hybrid",
        RetrievalMode.None => "none",
        _ => mode.ToString(),
    };
}
