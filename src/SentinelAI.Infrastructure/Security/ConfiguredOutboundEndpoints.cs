using Microsoft.Extensions.Configuration;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;
using SentinelAI.Infrastructure.Observability;

namespace SentinelAI.Infrastructure.Security;

/// <summary>
/// Reports every endpoint this deployment has been <em>configured</em> to send job content to.
/// </summary>
/// <remarks>
/// <para>
/// <b>Only explicitly configured endpoints are reported, on purpose.</b> A provider left on
/// its compiled-in default (<c>api.anthropic.com</c>, <c>integrate.api.nvidia.com</c>) is not
/// listed here, because those constants are the same vendor hosts the allowlist already
/// contains — checking them would be checking a literal against itself, which is precisely
/// the kind of assertion that cannot fail. The only way to direct job content somewhere other
/// than a supported vendor is to <em>set</em> an endpoint, and every set endpoint is reported.
/// </para>
/// <para>
/// Read through <see cref="ModelOptionsLoader"/> rather than a plain <c>Bind</c>, so the
/// per-agent endpoints are seen the same way the client factory sees them. A guard that read
/// the configuration differently from the code it guards would pass on a configuration the
/// factory then ignored — or worse, pass on a configuration the factory then used.
/// </para>
/// </remarks>
public sealed class ConfiguredOutboundEndpoints : IOutboundEndpointCatalog
{
    /// <summary>Where SEC-09's vector store URL will be read from once it exists.</summary>
    public const string KnowledgeEndpointKey = "SentinelAI:Knowledge:Endpoint";

    public ConfiguredOutboundEndpoints(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var models = ModelOptionsLoader.Load(configuration);
        var endpoints = new List<OutboundEndpoint>();

        // The shared endpoint, then each agent's override. Both are collected rather than
        // just the effective one: an override that is never reached today becomes reachable
        // the moment a role is retiered, and a guard that only saw the winner would have
        // approved it in advance.
        Add(endpoints, $"{ModelProviderOptions.SectionName}:Endpoint", models.Endpoint, EgressPurpose.Llm);

        foreach (var role in DebateWorkflow.ModelBackedRoles)
        {
            Add(endpoints,
                $"{ModelProviderOptions.SectionName}:Agents:{role}:Endpoint",
                models.For(role)?.Endpoint,
                EgressPurpose.Llm);
        }

        Add(endpoints, KnowledgeEndpointKey, configuration[KnowledgeEndpointKey], EgressPurpose.Rag);

        // SEC-36's collector — reported only when the traces carry prompts and completions.
        //
        // The distinction is the whole of this block's correctness. A metadata-only trace holds
        // a token count, a tier, a latency and a role name: none of it is the customer's, and
        // requiring an allowlist entry for it would push operators to leave observability off,
        // or to add a blanket host and mean nothing by it. A trace carrying the prompts is a
        // second destination for job content beside the model provider, and it belongs in front
        // of the same check the provider endpoint passes.
        var tracing = TracingOptionsLoader.Load(configuration);

        if (tracing.CaptureContent)
        {
            Add(endpoints,
                $"{TracingOptions.SectionName}:OtlpEndpoint",
                tracing.OtlpEndpoint,
                EgressPurpose.Telemetry);
        }

        Endpoints = endpoints;
    }

    public IReadOnlyList<OutboundEndpoint> Endpoints { get; }

    /// <summary>
    /// Adds a configured value, keeping an unparseable one rather than dropping it.
    /// </summary>
    /// <remarks>
    /// A value that is not a URI is turned into a relative <see cref="Uri"/>, which the policy
    /// then denies with "not an absolute URI". Dropping it instead would mean a typo in an
    /// endpoint silently produced an empty catalog and a clean pass — a check that reports
    /// "no configured endpoints" for a deployment that plainly has one.
    /// </remarks>
    private static void Add(List<OutboundEndpoint> into, string name, string? value, EgressPurpose purpose)
    {
        if (string.IsNullOrWhiteSpace(value)) return;

        var text = value.Trim();

        Uri uri;
        if (Uri.TryCreate(text, UriKind.Absolute, out var absolute)) uri = absolute;
        else if (Uri.TryCreate(text, UriKind.Relative, out var relative)) uri = relative;
        else uri = new Uri(Uri.EscapeDataString(text), UriKind.Relative);

        into.Add(new OutboundEndpoint(name, uri, purpose));
    }
}
