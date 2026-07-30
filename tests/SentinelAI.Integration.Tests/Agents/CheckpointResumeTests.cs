using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Executors;
using SentinelAI.Infrastructure.Agents.Orchestration;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// SEC-02 AC2: mid-run failure → resume from checkpoint without re-running completed turns.
/// </summary>
public class CheckpointResumeTests
{
    [Fact]
    public async Task Resuming_after_a_mid_run_failure_does_not_rerun_completed_turns()
    {
        // Blue detonates on its first invocation, then behaves. Red has already completed
        // by then, so Red is the turn we assert is NOT repeated.
        var blueShouldFail = 1;
        var debate = TestDebate.Create(blue: (_, _) =>
            Interlocked.Exchange(ref blueShouldFail, 0) == 1
                ? throw new InvalidOperationException("Blue crashed mid-debate.")
                : TestDebate.Converges);

        var runner = new DebateRunner(debate.Workflow);

        // --- first attempt: dies inside Blue -------------------------------------
        var failed = await runner.RunAsync(ScanBrief.Stub());

        Assert.Null(failed.Audit);
        Assert.Equal(1, debate.RedClient.CallCount);
        Assert.Equal(1, debate.BlueClient.CallCount);
        Assert.NotEmpty(failed.Checkpoints);

        // --- resume from the last checkpoint before the crash --------------------
        var resumed = await runner.ResumeAsync(failed.Checkpoints[^1]);

        // The debate finished.
        Assert.NotNull(resumed.Audit);
        Assert.True(resumed.Audit!.Converged);

        // The heart of the AC: Red ran once across BOTH attempts. Its completed turn was
        // restored from the checkpoint rather than recomputed.
        Assert.Equal(1, debate.RedClient.CallCount);

        // Blue ran twice — once to fail, once to succeed. That is a retry, not a re-run.
        Assert.Equal(2, debate.BlueClient.CallCount);
        Assert.Equal(1, debate.ReporterClient.CallCount);

        // Shared state survived the restart intact: Red's original turn is in the audit.
        Assert.Contains("ASSERT", resumed.Audit.Transcript[0].Content);
        Assert.Equal(3, resumed.Audit.Transcript.Count);
    }

    [Fact]
    public async Task A_completed_run_writes_checkpoints()
    {
        var debate = TestDebate.Create();
        var runner = new DebateRunner(debate.Workflow);

        var result = await runner.RunAsync(ScanBrief.Stub());

        Assert.NotNull(result.Audit);
        Assert.NotEmpty(result.Checkpoints);
        Assert.False(string.IsNullOrWhiteSpace(result.SessionId));
    }

    [Fact]
    public async Task Checkpoints_survive_a_process_restart_on_disk()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sentinelai-cp-" + Guid.NewGuid().ToString("N"));
        try
        {
            var blueShouldFail = 1;
            var debate = TestDebate.Create(blue: (_, _) =>
                Interlocked.Exchange(ref blueShouldFail, 0) == 1
                    ? throw new InvalidOperationException("Blue crashed mid-debate.")
                    : TestDebate.Converges);

            DebateResult failed;
            var store = DebateRunner.OpenFileStore(dir);
            try
            {
                failed = await new DebateRunner(debate.Workflow, DebateRunner.Persistent(store))
                    .RunAsync(ScanBrief.Stub());
            }
            finally
            {
                // Closing the store is the process exiting.
                store.Dispose();
            }

            Assert.Null(failed.Audit);
            Assert.NotEmpty(Directory.GetFileSystemEntries(dir));

            // A brand-new store and runner over the same directory — this is what
            // "restart the process and pick up where it left off" actually means.
            var revivedStore = DebateRunner.OpenFileStore(dir);
            try
            {
                var resumed = await new DebateRunner(debate.Workflow, DebateRunner.Persistent(revivedStore))
                    .ResumeAsync(failed.Checkpoints[^1]);

                Assert.NotNull(resumed.Audit);
                Assert.Equal(1, debate.RedClient.CallCount);
            }
            finally
            {
                revivedStore.Dispose();
            }
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }
}
