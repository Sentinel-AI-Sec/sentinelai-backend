using Microsoft.Agents.AI.Workflows;
using Microsoft.Agents.AI.Workflows.Checkpointing;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Executors;

namespace SentinelAI.Infrastructure.Agents.Orchestration;

/// <summary>What a completed (or halted) debate produced.</summary>
public sealed record DebateResult
{
    /// <summary>The adjudicated audit, if the Reporter ran.</summary>
    public DraftAudit? Audit { get; init; }

    /// <summary>Every agent turn observed during this run, in order.</summary>
    public required IReadOnlyList<DebateTurn> Turns { get; init; }

    /// <summary>Checkpoints written during this run, oldest first.</summary>
    public required IReadOnlyList<CheckpointInfo> Checkpoints { get; init; }

    /// <summary>
    /// Executor and workflow failures the framework reported during this run — a bad key, a
    /// network error, a rate limit — captured so a run that ends without an audit says why
    /// rather than just how far it got. Empty on a clean run.
    /// </summary>
    public required IReadOnlyList<string> Failures { get; init; }

    /// <summary>The session the run belongs to. Needed to resume it.</summary>
    public required string SessionId { get; init; }

    public bool Completed => Audit is not null;
}

/// <summary>
/// Runs the debate workflow with checkpointing, and resumes it from a checkpoint.
/// </summary>
/// <remarks>
/// Checkpointing is the Agent Framework's, not ours: it snapshots shared session state
/// after every superstep. Resuming from the last checkpoint therefore picks up with the
/// completed turns already in state — they are not re-executed.
/// </remarks>
public sealed class DebateRunner(Workflow workflow, CheckpointManager? checkpoints = null)
{
    private readonly Workflow _workflow = workflow ?? throw new ArgumentNullException(nameof(workflow));
    private readonly CheckpointManager _checkpoints = checkpoints ?? CheckpointManager.CreateInMemory();

    /// <summary>The checkpoint manager backing this runner, for resume calls.</summary>
    public CheckpointManager Checkpoints => _checkpoints;

    /// <summary>
    /// Opens a disk-backed checkpoint store, creating the directory if needed.
    /// </summary>
    /// <remarks>
    /// The store keeps its index file open, so the caller owns it and must dispose it —
    /// which is also how you release the directory for a genuine process restart.
    /// </remarks>
    public static FileSystemJsonCheckpointStore OpenFileStore(string directory) =>
        new(Directory.CreateDirectory(directory));

    /// <summary>Wraps a checkpoint store as a manager the runner can use.</summary>
    public static CheckpointManager Persistent(FileSystemJsonCheckpointStore store) =>
        CheckpointManager.CreateJson(store);

    /// <summary>Starts a fresh debate.</summary>
    /// <param name="onEvent">
    /// Invoked as each workflow event arrives. Supply it to report progress while the
    /// debate is still running — a live model takes tens of seconds per turn, and a run
    /// that prints nothing until it finishes is indistinguishable from one that has hung.
    /// </param>
    public async Task<DebateResult> RunAsync(
        ScanBrief brief,
        Action<WorkflowEvent>? onEvent = null,
        string? sessionId = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(brief);

        // Disposed before returning: a Workflow may only be owned by one runner at a
        // time, and a failed run must release it so the resume can claim it.
        await using var run = await InProcessExecution
            .RunStreamingAsync(_workflow, brief, _checkpoints, sessionId, cancellationToken)
            .ConfigureAwait(false);

        return await CollectAsync(run, onEvent, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Resumes an interrupted debate from a checkpoint. Turns already completed when the
    /// checkpoint was taken are restored from state rather than re-run.
    /// </summary>
    public async Task<DebateResult> ResumeAsync(
        CheckpointInfo checkpoint,
        Action<WorkflowEvent>? onEvent = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);

        await using var run = await InProcessExecution
            .ResumeStreamingAsync(_workflow, checkpoint, _checkpoints, cancellationToken)
            .ConfigureAwait(false);

        return await CollectAsync(run, onEvent, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Drains the event stream to completion, forwarding each event to <paramref name="onEvent"/>
    /// as it arrives, and folds the result into a <see cref="DebateResult"/>.
    /// </summary>
    private static async Task<DebateResult> CollectAsync(
        StreamingRun run, Action<WorkflowEvent>? onEvent, CancellationToken cancellationToken)
    {
        DraftAudit? audit = null;
        var turns = new List<DebateTurn>();
        var failures = new List<string>();

        await foreach (var evt in run.WatchStreamAsync(cancellationToken).ConfigureAwait(false))
        {
            switch (evt)
            {
                case AgentTurnEvent turn:
                    turns.Add(turn.Turn);
                    break;
                case WorkflowOutputEvent { Data: DraftAudit produced }:
                    audit = produced;
                    break;

                // The framework reports an executor exception (a bad key, a network error, a
                // rate limit) as an event in this stream, not as a .NET exception thrown out of
                // WatchStreamAsync. Before this case existed, that exception was silently
                // dropped: the caller only ever saw "0 turns completed" with no indication a
                // model call had failed at all — the actual error, and everything about it, was
                // discarded here.
                case ExecutorFailedEvent failed:
                    failures.Add($"executor '{failed.ExecutorId}' failed: {failed.Data}");
                    break;
                case WorkflowErrorEvent error:
                    failures.Add($"workflow error: {error.Exception}");
                    break;
            }

            onEvent?.Invoke(evt);
        }

        return new DebateResult
        {
            Audit = audit,
            Turns = turns,
            Failures = failures,
            Checkpoints = run.Checkpoints,
            SessionId = run.SessionId
        };
    }
}
