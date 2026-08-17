namespace SentinelAI.Application.Features.Scan.Orchestration;

/// <summary>
/// The blocks of Pipeline B a failure can be attributed to (SEC-46).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is not <see cref="Domain.Enums.ScanStage"/>.</b> That enum records how far a job
/// <em>got</em>, and its values are the six milestones a job passes through. This one records
/// which block of the runner <em>threw</em>, and the two are not the same list: there is no
/// <c>ScanStage</c> value covering retrieve-plus-debate-plus-report, which is a single call into
/// <c>ThinSlicePipeline</c> and therefore a single catch. Reusing <c>ScanStage</c> would force a
/// choice between inventing a value on someone else's enum and writing one that is not true.
/// </para>
/// <para>
/// <b>Why only three.</b> The runner can attribute a failure exactly as precisely as it can
/// place a <c>try</c> boundary, and no more. Redaction is inside the normalize block because the
/// gate needs findings to redact and so cannot run before them; retrieve, debate and report are
/// one block because <c>ThinSlicePipeline.RunAsync</c> is one call. Naming a fourth stage the
/// runner cannot actually distinguish would put a guess in a column people will trust.
/// </para>
/// </remarks>
public enum ScanPipelineStage
{
    /// <summary>
    /// Reading the bundle's findings files, resolving rule mappings, redacting, and persisting
    /// the unified set (SEC-14/15/16, and the SEC-33 ingress gate).
    /// </summary>
    Normalize,

    /// <summary>
    /// Building the resource graph from the shipped Terraform, lock files and Dockerfiles, and
    /// traversing it for candidate chains (SEC-17/18/19/20).
    /// </summary>
    Graph,

    /// <summary>
    /// Retrieval, the Red/Blue/Reporter debate, the report, and retention (SEC-21/22, SEC-26/27,
    /// SEC-45, SEC-35) — everything behind the one call into <c>ThinSlicePipeline</c>.
    /// </summary>
    /// <remarks>
    /// The coarsest of the three, and the one whose failures are most varied: a corpus that is
    /// unreachable and a model provider that rate-limited both land here. The exception message
    /// on <c>FailureReason</c> and the stage logs are what separate them.
    /// </remarks>
    Audit,
}
