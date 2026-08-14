using System.Runtime.CompilerServices;
using Microsoft.Extensions.AI;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Agents.Providers;

/// <summary>
/// A deterministic, offline <see cref="IChatClient"/>. Every SEC-02 unit test runs
/// against this: no network, no API key, no token spend, and byte-identical output
/// across runs so checkpoint-resume can be asserted exactly.
/// </summary>
/// <remarks>
/// This is the whole point of the connector abstraction. The agents are real
/// <c>ChatClientAgent</c>s either way — swapping to NIM or Claude replaces this object
/// and changes nothing else.
/// </remarks>
public sealed class ScriptedChatClient : IChatClient
{
    private readonly Func<IReadOnlyList<ChatMessage>, ChatOptions?, string> _responder;
    private int _callCount;

    /// <summary>Number of times the client has been asked for a response.</summary>
    public int CallCount => Volatile.Read(ref _callCount);

    /// <summary>Every request the client has seen, for test assertions.</summary>
    public IReadOnlyList<IReadOnlyList<ChatMessage>> Requests => _requests;
    private readonly List<IReadOnlyList<ChatMessage>> _requests = [];
    private readonly Lock _gate = new();

    /// <summary>Creates a client driven by a caller-supplied responder.</summary>
    public ScriptedChatClient(Func<IReadOnlyList<ChatMessage>, ChatOptions?, string> responder)
        => _responder = responder ?? throw new ArgumentNullException(nameof(responder));

    /// <summary>
    /// Creates a client returning the canned turn for one debate role.
    /// </summary>
    /// <remarks>
    /// The role is passed in rather than inferred from the prompt. An earlier version
    /// sniffed the system message for the agent's name, which silently matched nothing:
    /// <c>ChatClientAgent</c> passes instructions via <see cref="ChatOptions.Instructions"/>,
    /// not as a <see cref="ChatRole.System"/> message. Being told the role removes the
    /// guesswork entirely.
    /// </remarks>
    public ScriptedChatClient(AgentRole role)
        => _responder = (_, _) => CannedTurnFor(role);

    /// <summary>The canned response for a role. Deterministic — no randomness, no clock.</summary>
    public static string CannedTurnFor(AgentRole role) => role switch
    {
        AgentRole.Red =>
            "ASSERT: pkg:Newtonsoft.Json (CWE-502) -> code:OrderController.Deserialize "
            + "-> infra:ecs_task.api -> iam_role:api-task-role -> s3:crown-jewels. "
            + "4 hops, seeded from the highest-severity finding.",

        AgentRole.Blue =>
            "VALIDATE: hop 1 confirmed against packages.lock.json. hop 2 confirmed against "
            + "the Roslyn finding. hop 3 image-name join is INFERRED. hop 4 confirmed "
            + "against the IAM policy. " + "No link broken.",

        AgentRole.Reporter =>
            "ADJUDICATE: chain survives Blue's rebuttal. Severity HIGH. "
            + "Weakest join is INFERRED at the code->infra seam.",

        // The Orchestrator does not debate. It has a canned turn only so that every role
        // is representable offline, and so a future orchestrator model call has a script.
        AgentRole.Orchestrator =>
            "SEQUENCE: debate seeded. Red asserts first; turn-cap enforced by the graph.",

        _ => throw new ArgumentOutOfRangeException(nameof(role), role, "No canned turn for this role.")
    };

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var list = messages as IReadOnlyList<ChatMessage> ?? [.. messages];
        Interlocked.Increment(ref _callCount);
        lock (_gate) { _requests.Add(list); }

        var text = _responder(list, options);
        return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, text))
        {
            ModelId = options?.ModelId ?? "scripted",
            ResponseId = $"scripted-{CallCount}",
            Usage = UsageFor(list, options, text)
        });
    }

    /// <summary>
    /// A deterministic stand-in for the token counts a real provider returns.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Usage is reported so the SEC-31 accounting path is exercised offline: without it every
    /// test and every credential-free run measures zero tokens, and an assertion that cost was
    /// recorded passes whether the plumbing works or not.
    /// </para>
    /// <para>
    /// These are <em>estimates</em>, on the usual four-characters-per-token rule of thumb, and
    /// they are not passed off as anything else. What stops them turning into invented money
    /// is that the Scripted provider's rate is a real zero — nothing leaves the process, so
    /// nothing is billed — and <c>ProviderPricing</c> prices it accordingly. Offline runs show
    /// a token breakdown and a cost of zero, both of which are true.
    /// </para>
    /// </remarks>
    private static UsageDetails UsageFor(
        IReadOnlyList<ChatMessage> messages, ChatOptions? options, string response) => new()
        {
            InputTokenCount = EstimateTokens(options?.Instructions)
                + messages.Sum(m => EstimateTokens(m.Text)),
            OutputTokenCount = EstimateTokens(response)
        };

    private static long EstimateTokens(string? text) =>
        string.IsNullOrEmpty(text) ? 0 : (text.Length + 3) / 4;

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var response = await GetResponseAsync(messages, options, cancellationToken).ConfigureAwait(false);
        foreach (var message in response.Messages)
            yield return new ChatResponseUpdate(message.Role, message.Contents);
    }

    public object? GetService(Type serviceType, object? serviceKey = null)
    {
        ArgumentNullException.ThrowIfNull(serviceType);
        return serviceKey is null && serviceType.IsInstanceOfType(this) ? this : null;
    }

    public void Dispose() { }
}
