namespace SentinelAI.Domain.Models;

/// <summary>
/// The four roles in the debate, per AID-01 section 3.1.
/// </summary>
public enum AgentRole
{
    /// <summary>
    /// The conductor. Sequences the debate, seeds shared state, and briefs Red by analysing
    /// the resource graph — but asserts nothing about security itself. It makes a model call
    /// of its own and so needs its own credential; see <c>ModelProviderOptions.Agents</c>.
    /// </summary>
    Orchestrator,

    Red,
    Blue,
    Reporter
}
