using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Executors;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// Builds a debate wired to one <see cref="ScriptedChatClient"/> per role, so a test can
/// script each agent independently and count exactly how many times each one was invoked.
/// That call count is what proves a resumed run does not re-execute completed turns.
/// </summary>
internal sealed class TestDebate
{
    public required ScriptedChatClient RedClient { get; init; }
    public required ScriptedChatClient BlueClient { get; init; }
    public required ScriptedChatClient ReporterClient { get; init; }
    public required Workflow Workflow { get; init; }
    public required int MaxRounds { get; init; }

    /// <summary>Blue's canned verdict that ends the debate by convergence.</summary>
    public const string Converges =
        "VALIDATE: every hop confirmed against the real configuration. " + BlueTeamExecutor.ConvergenceMarker;

    /// <summary>Blue's canned verdict that keeps the debate going until the turn-cap stops it.</summary>
    public const string NeverConverges = "VALIDATE: Link broken at hop 3. Re-assert with a different pivot.";

    public static TestDebate Create(
        int maxRounds = 3,
        Func<IReadOnlyList<ChatMessage>, ChatOptions?, string>? red = null,
        Func<IReadOnlyList<ChatMessage>, ChatOptions?, string>? blue = null,
        Func<IReadOnlyList<ChatMessage>, ChatOptions?, string>? reporter = null)
    {
        var redClient = new ScriptedChatClient(red ?? ((_, _) => "ASSERT: dep -> code -> infra -> bucket."));
        var blueClient = new ScriptedChatClient(blue ?? ((_, _) => Converges));
        var reporterClient = new ScriptedChatClient(reporter ?? ((_, _) => "ADJUDICATE: chain survives. Severity HIGH."));

        var workflow = DebateWorkflow.Build(
            new OrchestratorExecutor(),
            new RedTeamExecutor(Agent(redClient, "RedTeam", RedTeamExecutor.Instructions)),
            new BlueTeamExecutor(Agent(blueClient, "BlueTeam", BlueTeamExecutor.Instructions)),
            new ReporterExecutor(Agent(reporterClient, "Reporter", ReporterExecutor.Instructions), maxRounds),
            maxRounds);

        return new TestDebate
        {
            RedClient = redClient,
            BlueClient = blueClient,
            ReporterClient = reporterClient,
            Workflow = workflow,
            MaxRounds = maxRounds
        };
    }

    private static AIAgent Agent(IChatClient client, string name, string instructions) =>
        new ChatClientAgent(client, instructions: instructions, name: name);
}
