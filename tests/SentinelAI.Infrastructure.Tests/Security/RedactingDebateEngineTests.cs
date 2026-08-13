using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Security;

namespace SentinelAI.Infrastructure.Tests.Security;

/// <summary>
/// SEC-33 at the model boundary. The gate covers the scan pipeline; this covers the call
/// itself, which is the only place "no secret reaches the model" stops being a claim about a
/// code path and becomes a property of the boundary.
/// </summary>
public class RedactingDebateEngineTests
{
    /// <summary>Records the brief it was handed, so a test can inspect what a model would see.</summary>
    private sealed class SpyEngine : IDebateEngine
    {
        public ScanBrief? Received { get; private set; }

        public Task<DraftAudit> RunAsync(ScanBrief brief, CancellationToken ct = default)
        {
            Received = brief;
            return Task.FromResult(new DraftAudit
            {
                Summary = "stub",
                Transcript = [],
                Rounds = 1,
                TerminatedByTurnCap = false,
                Converged = true,
                WeakestJoin = Confidence.Certain,
            });
        }
    }

    private static (RedactingDebateEngine Engine, SpyEngine Spy) Build()
    {
        var spy = new SpyEngine();
        return (new RedactingDebateEngine(
            spy, new RegexSecretScanner(), NullLogger<RedactingDebateEngine>.Instance), spy);
    }

    [Fact]
    public async Task Redacts_a_secret_that_reached_the_boundary_unredacted()
    {
        // POST /v1/debates takes a brief as free text straight from a caller: it never passes
        // through ingest, so the gate cannot have cleaned it. This is not hypothetical.
        var (engine, spy) = Build();
        var brief = new ScanBrief("job-1", "Findings:\n  F1: ENV APP_API_KEY=\"livekey1234567890\"");

        await engine.RunAsync(brief);

        Assert.NotNull(spy.Received);
        Assert.DoesNotContain("livekey1234567890", spy.Received!.Context, StringComparison.Ordinal);
        Assert.Contains("[REDACTED:", spy.Received.Context, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Still_runs_the_debate_after_redacting()
    {
        // Refusing to run would turn a contained near-miss into an outage. The redaction is
        // the mitigation; stopping the scan is not.
        var (engine, spy) = Build();

        var audit = await engine.RunAsync(new ScanBrief("job-1", "token = ghp_1234567890abcdefghijklmnopqrstuvwxyz"));

        Assert.NotNull(audit);
        Assert.NotNull(spy.Received);
    }

    [Fact]
    public async Task Passes_a_clean_brief_through_untouched()
    {
        // The normal case: the gate already cleaned it, so this must be a no-op — including
        // not reallocating the brief, which would make the backstop look like it fired.
        var (engine, spy) = Build();
        var brief = ScanBrief.Stub("job-1");

        await engine.RunAsync(brief);

        Assert.Same(brief, spy.Received);
    }

    [Fact]
    public async Task Keeps_the_scan_job_id_when_it_redacts()
    {
        // The brief is rewritten with a `with` expression; dropping the correlation id would
        // detach the debate from its job exactly when something has gone wrong upstream.
        var (engine, spy) = Build();

        await engine.RunAsync(new ScanBrief("job-42", "api_key = abcdefgh12345678"));

        Assert.Equal("job-42", spy.Received!.ScanJobId);
    }
}
