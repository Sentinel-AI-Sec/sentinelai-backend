using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Executors;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Infrastructure.Agents.Orchestration;

/// <summary>
/// Builds the Red → Blue → Reporter debate graph.
/// </summary>
/// <remarks>
/// <para>The shape, and why:</para>
/// <code>
///   Orchestrator ──> Red ──> Blue ──[not converged AND round &lt; cap]──> Red   (loop)
///                                 └─[converged OR round >= cap]──────> Reporter
/// </code>
/// <para>
/// Both exit conditions land on the Reporter, so the Reporter runs — and outputs — on
/// every terminating path including the turn-cap one.
/// </para>
/// </remarks>
public static class DebateWorkflow
{
    /// <summary>
    /// The agents that actually make a model call, and therefore need a credential.
    /// </summary>
    public static readonly IReadOnlyList<AgentRole> ModelBackedRoles =
        [AgentRole.Orchestrator, AgentRole.Red, AgentRole.Blue, AgentRole.Reporter];

    /// <summary>Builds the workflow from an explicit chat-client factory.</summary>
    public static Workflow Build(IChatClientFactory clients, DebateOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(clients);
        options ??= new DebateOptions();
        options.Validate();

        var orchestrator = new OrchestratorExecutor(
            CreateAgent(clients, options, AgentRole.Orchestrator, "Orchestrator", OrchestratorExecutor.Instructions));
        var red = new RedTeamExecutor(
            CreateAgent(clients, options, AgentRole.Red, "RedTeam", RedTeamExecutor.Instructions));
        var blue = new BlueTeamExecutor(
            CreateAgent(clients, options, AgentRole.Blue, "BlueTeam", BlueTeamExecutor.Instructions));
        var reporter = new ReporterExecutor(
            CreateAgent(clients, options, AgentRole.Reporter, "Reporter", ReporterExecutor.Instructions),
            options.MaxRounds);

        return Build(orchestrator, red, blue, reporter, options.MaxRounds);
    }

    /// <summary>Builds the workflow from pre-constructed executors. Used by tests.</summary>
    public static Workflow Build(
        OrchestratorExecutor orchestrator,
        RedTeamExecutor red,
        BlueTeamExecutor blue,
        ReporterExecutor reporter,
        int maxRounds)
    {
        var orchestratorNode = new ExecutorInstanceBinding(orchestrator);
        var redNode = new ExecutorInstanceBinding(red);
        var blueNode = new ExecutorInstanceBinding(blue);
        var reporterNode = new ExecutorInstanceBinding(reporter);

        return new WorkflowBuilder(orchestratorNode)
            .AddEdge(orchestratorNode, redNode)
            .AddEdge(redNode, blueNode)
            // These two predicates must partition every possible state, including null:
            // if neither fires the run stalls at Blue with no verdict. A null message
            // therefore falls through to the Reporter, so termination is never at risk.
            //
            // Keep debating: Blue broke a link and the cap still has room.
            .AddEdge(blueNode, redNode,
                (DebateTurn? t) => t is not null && t.VerdictReadable && !t.Converged && t.Round < maxRounds)
            // Adjudicate: the debate converged, the turn-cap stopped it, or state was lost.
            // Re-asking a model that already failed to produce a verdict just spends the
            // cap on the same failure, so an unreadable verdict exits here too.
            .AddEdge(blueNode, reporterNode,
                (DebateTurn? t) => t is null || !t.VerdictReadable || t.Converged || t.Round >= maxRounds)
            .WithOutputFrom(reporterNode)
            .WithName("SentinelAI.Debate")
            .WithDescription("Red asserts, Blue validates, Reporter adjudicates.")
            .Build();
    }

    private static AIAgent CreateAgent(
        IChatClientFactory clients, DebateOptions options, AgentRole role, string name, string instructions) =>
        new ChatClientAgent(
            clients.Create(role, options.TierFor(role)),
            new ChatClientAgentOptions
            {
                Name = name,
                Description = $"SentinelAI {role} agent.",

                // Instructions belong on ChatOptions, not alongside Name/Description —
                // that is where ChatClientAgent reads them from. Setting ChatOptions here
                // without carrying Instructions across would silently unset the agent's
                // persona and leave every role answering identically.
                ChatOptions = new ChatOptions
                {
                    Instructions = instructions,
                    MaxOutputTokens = options.MaxOutputTokens,
                    Temperature = options.Temperature
                }
            });
}
