using System.Runtime.CompilerServices;
using Microsoft.Extensions.AI;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Executors;

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
    /// <remarks>
    /// Written in the labelled line shape each role's <c>Instructions</c> now mandate, and
    /// against the node labels of <see cref="ScanBrief.Stub"/> — the brief every offline run is
    /// handed. That is what makes an offline run demonstrate the real thing: the hops resolve to
    /// real node keys, Blue's verdicts attach to them, and the mechanical edge check passes,
    /// so the transcript renders exactly as a live one does. The previous canned turns named
    /// resources (<c>s3:crown-jewels</c>) that appear in no graph, so every reader of the
    /// transcript — the edge validator included — correctly found nothing in them.
    /// </remarks>
    public static string CannedTurnFor(AgentRole role) => role switch
    {
        AgentRole.Red =>
            """
            HOP 1: N1 -> used-by -> N2 | none | F1: packages.lock.json pins commons-collections 3.2.1 and AppDataHandler imports InvokerTransformer
            HOP 2: N2 -> deployed-as -> N4 | none | the api-service task definition references acme/api by tag
            HOP 3: N4 -> assumes -> N6 | none | the api-service task definition sets taskRoleArn to api-task-role
            HOP 4: N6 -> can-access -> N8 | none | F4: the inline policy grants s3:GetObject on customer-data-bucket/*
            CHAIN: N1 -> N2 -> N4 -> N6 -> N8
            IMPACT: unauthenticated deserialization ends in read/write access to customer PII.
            """,

        AgentRole.Blue =>
            $"""
            HOP 1: N1 -> N2 | CONFIRMED | the lock file and the import in F1 both name the gadget class
            HOP 2: N2 -> N4 | UNRESOLVED | U1: the image is joined by mutable tag, not by digest — no digest was recorded
            HOP 3: N4 -> N6 | CONFIRMED | the task definition's taskRoleArn names api-task-role outright
            HOP 4: N6 -> N8 | CONFIRMED | F4 grants s3:Get/PutObject on customer-data-bucket/*
            {BlueTeamExecutor.HoldsVerdict}
            """,

        AgentRole.Reporter =>
            """
            CHAIN: N1 -> N2 -> N4 -> N6 -> N8
            SEVERITY: high — a CVSS 9.8 deserialization gadget chain ends at the crown jewel
            CONFIDENCE: inferred — the weakest join is N2 -> N4
            IMPACT: an attacker reaching the deserialization sink can read and write customer PII in customer-data-bucket.
            EVIDENCE: F1 for the gadget chain, F4 for the bucket grant, U1 for the unproven image join
            NEXT: record the deployed image digest and compare it against the api-service task definition.
            """,

        // The Orchestrator does not debate. It has a canned turn only so that every role
        // is representable offline, and so a future orchestrator model call has a script.
        AgentRole.Orchestrator =>
            """
            TARGET: N8, the customer-data-bucket holding customer PII.
            LEAD: F1 — commons-collections 3.2.1 (CVE-2015-6420, CVSS 9.8) reaches two deserialization sinks.
            ROUTE: dependency to application code to the running task to its IAM role to the bucket.
            WEAK JOIN: N2 -> N4, joined by image tag rather than digest — a recorded digest would settle it.
            """,

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
