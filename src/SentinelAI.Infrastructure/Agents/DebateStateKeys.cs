namespace SentinelAI.Infrastructure.Agents;

/// <summary>
/// Where the shared <c>DebateState</c> lives inside the Agent Framework's workflow context.
/// </summary>
/// <remarks>
/// These are runtime addressing details, not domain concepts, so they sit in Infrastructure
/// rather than on the record itself. Changing them changes where a checkpoint looks for its
/// state, which is exactly the kind of decision that should not be reachable from Domain.
/// </remarks>
public static class DebateStateKeys
{
    /// <summary>State key under which the debate state lives in <c>IWorkflowContext</c>.</summary>
    public const string State = "sentinel.debate.state";

    /// <summary>Scope shared by all executors so they see one another's turns.</summary>
    public const string SharedScope = "sentinel.debate";
}
