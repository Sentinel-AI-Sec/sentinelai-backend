using Microsoft.Extensions.AI;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Executors;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Agents.Demo;

/// <summary>
/// Chooses the backing model for a demo scenario.
/// </summary>
/// <remarks>
/// For a live provider it simply delegates to the production
/// <see cref="ChatClientFactory"/> — the demo does not get its own model path. For the
/// offline scenarios it supplies a role-aware scripted client, since the sprint demo has
/// to show a debate that fails to converge and one that crashes mid-run, neither of which
/// the default happy-path script produces.
/// </remarks>
internal sealed class DemoChatClientFactory(ModelProviderOptions options, Scenario scenario)
    : IChatClientFactory
{
    private readonly ChatClientFactory _live = new(options);
    private readonly ModelProviderOptions _options = options;
    private int _blueShouldCrash = scenario == Scenario.Resume ? 1 : 0;

    public IChatClient Create(AgentRole role, ModelTier tier) =>
        _options.Provider == ModelProvider.Scripted
            ? new ScriptedChatClient((_, _) => Script(role))
            : new SpinnerChatClient(_live.Create(role, tier), role);

    private string Script(AgentRole role) => role switch
    {
        AgentRole.Orchestrator =>
            "BRIEFING: Highest-severity finding is CVE-2015-6420 in commons-collections:3.2.1 (CVSS 9.8). "
            + "Strongest path runs N1→N2→N3→N4→N5. Weak join at N2→N3 (image-name convention). "
            + "Red should seed from F1 and exploit the full 4-hop chain to the crown-jewel bucket.",

        AgentRole.Red =>
            "ASSERT: pkg:Newtonsoft.Json 12.0.1 (CWE-502) -> code:OrderController.Deserialize "
            + "-> infra:ecs_task.api -> iam_role:api-task-role -> s3:crown-jewels",

        AgentRole.Blue => BlueVerdict(),

        AgentRole.Reporter => ReporterVerdict(),

        _ => throw new ArgumentOutOfRangeException(nameof(role), role, null)
    };

    private string BlueVerdict()
    {
        // Fail exactly once, to demonstrate checkpoint recovery.
        if (Interlocked.Exchange(ref _blueShouldCrash, 0) == 1)
            throw new InvalidOperationException("Blue Team agent crashed mid-debate (simulated).");

        return scenario switch
        {
            // Breaks a link every round, so only the turn-cap can stop the debate.
            Scenario.TurnCap =>
                "VALIDATE: hop 3 image-name join does not match the Terraform image field. "
                + "Link broken at hop 3. Re-assert with a different pivot.",

            // Contains UNRESOLVED *and* the convergence marker on purpose. Blue cannot
            // confirm a load-bearing join, but it does not break the chain either - so the
            // chain survives to the Reporter carrying Confidence.Unresolved. That is
            // AID-01 3.3's "does not kill the chain silently".
            Scenario.Unresolved =>
                "VALIDATE: hop 1 confirmed against packages.lock.json. hop 2 confirmed against "
                + "the Roslyn finding. hop 3 image-name join is UNRESOLVED - the Terraform "
                + "image field is a dynamic tag I cannot resolve to the Dockerfile image. "
                + "hop 4 confirmed against the IAM policy. No link is broken, but hop 3 is "
                + "unconfirmed. " + BlueTeamExecutor.ConvergenceMarker,

            _ =>
                "VALIDATE: hop 1 confirmed against packages.lock.json. hop 2 confirmed against "
                + "the Roslyn finding. hop 3 image-name join is INFERRED. hop 4 confirmed against "
                + "the IAM policy. " + BlueTeamExecutor.ConvergenceMarker
        };
    }

    private string ReporterVerdict() => scenario switch
    {
        Scenario.TurnCap =>
            "ADJUDICATE: no chain survived validation within the turn-cap. "
            + "Nothing is asserted as confirmed.",

        Scenario.Unresolved =>
            "ADJUDICATE: potential chain, unverified join at the code->infra seam. "
            + "Reported for human confirmation - NOT a confirmed verdict.",

        _ =>
            "ADJUDICATE: chain survives Blue's rebuttal. Severity HIGH, exploitability HIGH. "
            + "Weakest join is INFERRED at the code->infra seam."
    };
}

internal enum Scenario
{
    /// <summary>Happy path: Red asserts, Blue cannot break it, Reporter adjudicates.</summary>
    Debate,

    /// <summary>Blue never converges, so the turn-cap terminates the run.</summary>
    TurnCap,

    /// <summary>Blue crashes once; the run resumes from its last checkpoint.</summary>
    Resume,

    /// <summary>
    /// Blue cannot confirm a load-bearing join. The chain is not broken and still reaches
    /// the Reporter, which surfaces it as a potential chain with an unverified join rather
    /// than dropping it or asserting it as confirmed (AID-01 3.3 and 7).
    /// </summary>
    Unresolved
}
