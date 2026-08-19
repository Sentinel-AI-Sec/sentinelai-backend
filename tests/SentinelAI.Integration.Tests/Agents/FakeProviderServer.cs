using System.ClientModel.Primitives;
using System.Net;
using System.Text;
using System.Text.Json;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Agents.Executors;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// One request this stand-in provider received, kept for assertions about the wire format.
/// </summary>
/// <param name="Uri">Full request URI, including the query string.</param>
/// <param name="AuthorizationScheme">Scheme of the <c>Authorization</c> header, if present.</param>
/// <param name="AuthorizationValue">Credential carried by <c>Authorization</c>, if present.</param>
/// <param name="ApiKeyHeader">Value of the <c>api-key</c> header, if present.</param>
/// <param name="Body">The JSON request body.</param>
internal sealed record ProviderCall(
    Uri Uri,
    string? AuthorizationScheme,
    string? AuthorizationValue,
    string? ApiKeyHeader,
    string Body);

/// <summary>
/// A stand-in OpenAI-wire provider: speaks the real HTTP protocol, answers in character for
/// whichever agent is calling, and records every request — without a network or a credential.
/// </summary>
/// <remarks>
/// <para>
/// This is what makes SEC-30's acceptance criterion testable. Proving "switching provider is a
/// config change" needs a debate that actually <em>runs</em> on a second provider, and until
/// now that was impossible offline: the live branches of <c>ChatClientFactory</c> could only be
/// checked by looking at the type of client they returned. Everything those branches really do
/// — auth header, URL shape, deployment name, model id, response translation — went untested,
/// which is exactly how the Azure branch stayed broken.
/// </para>
/// <para>
/// It is an <see cref="HttpMessageHandler"/> rather than a hand-written
/// <see cref="PipelineTransport"/> because System.ClientModel already adapts one
/// (<see cref="HttpClientPipelineTransport"/>), and the real HTTP stack above it — headers,
/// URI building, content negotiation — then stays in the test rather than being stubbed out.
/// </para>
/// </remarks>
internal sealed class FakeProviderServer : HttpMessageHandler
{
    private readonly List<ProviderCall> _calls = [];
    private readonly Lock _gate = new();

    /// <summary>Every request received, in order.</summary>
    public IReadOnlyList<ProviderCall> Calls
    {
        get { lock (_gate) return [.. _calls]; }
    }

    /// <summary>Requests received for one agent.</summary>
    public IEnumerable<ProviderCall> CallsFor(AgentRole role) =>
        Calls.Where(c => RoleOf(c.Body) == role);

    /// <summary>Wraps this handler as the transport a <c>ChatClientFactory</c> can be given.</summary>
    public PipelineTransport AsTransport() => new HttpClientPipelineTransport(new HttpClient(this));

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken);

        lock (_gate)
        {
            _calls.Add(new ProviderCall(
                request.RequestUri!,
                request.Headers.Authorization?.Scheme,
                request.Headers.Authorization?.Parameter,
                request.Headers.TryGetValues("api-key", out var apiKey) ? apiKey.FirstOrDefault() : null,
                body));
        }

        var reply = CannedReplyFor(RoleOf(body));

        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(ChatCompletionJson(reply), Encoding.UTF8, "application/json")
        };
    }

    /// <summary>
    /// Which agent is calling, read from the instructions carried in the request body.
    /// </summary>
    /// <remarks>
    /// Matched on the full "You are the X agent" opening rather than on the role name alone:
    /// the Orchestrator's instructions mention the Red Team agent, so a looser match routes
    /// the Orchestrator's own call to Red and the debate answers the wrong thing.
    /// </remarks>
    private static AgentRole? RoleOf(string body)
    {
        if (body.Contains("You are the Orchestrator agent", StringComparison.Ordinal)) return AgentRole.Orchestrator;
        if (body.Contains("You are the Red Team agent", StringComparison.Ordinal)) return AgentRole.Red;
        if (body.Contains("You are the Blue Team agent", StringComparison.Ordinal)) return AgentRole.Blue;
        if (body.Contains("You are the Reporter agent", StringComparison.Ordinal)) return AgentRole.Reporter;
        return null;
    }

    /// <summary>
    /// What this provider "says". Blue converges on the first round, so a debate driven by
    /// this server terminates through the convergence path rather than the turn cap.
    /// </summary>
    private static string CannedReplyFor(AgentRole? role) => role switch
    {
        AgentRole.Orchestrator => "SEQUENCE: seed from the CWE-502 finding; Red asserts first.",
        AgentRole.Red => "ASSERT: pkg:newtonsoft.json:9.0.1 -> code:orderservice.deserialize "
                         + "-> task:ecs-task/api-service -> s3:customer-data-bucket.",
        AgentRole.Blue => "VALIDATE: every hop confirmed against the supplied configuration. "
                          + BlueTeamExecutor.ConvergenceMarker,
        AgentRole.Reporter => "ADJUDICATE: chain survives. Severity HIGH.",
        _ => "ACK."
    };

    /// <summary>A minimal but genuine OpenAI chat-completion response.</summary>
    private static string ChatCompletionJson(string content) => JsonSerializer.Serialize(new
    {
        id = "chatcmpl-fake",
        @object = "chat.completion",
        created = 1_700_000_000L,
        model = "fake-model",
        choices = new[]
        {
            new
            {
                index = 0,
                message = new { role = "assistant", content },
                finish_reason = "stop"
            }
        },
        usage = new { prompt_tokens = 10, completion_tokens = 20, total_tokens = 30 }
    });
}
