using Microsoft.Extensions.Configuration;
using SentinelAI.Application.Features.Scan.Security;

namespace SentinelAI.Infrastructure.Security;

/// <summary>
/// Operator additions to the compiled-in egress allowlist, bound from
/// <c>Security:Egress</c>.
/// </summary>
/// <remarks>
/// Additions only — there is no way to <em>remove</em> a vendor default or to switch the
/// check off from configuration. A kill switch is the first thing reached for when a
/// deployment is misconfigured at 2am, and a guard that can be turned off by the same file
/// that misconfigured it is not a guard. If a real deployment needs a host that is not here,
/// it names it, and the name is in the configuration for an auditor to read.
/// </remarks>
public sealed class EgressOptions
{
    public const string SectionName = "Security:Egress";

    /// <summary>
    /// Extra inference hosts — a self-hosted gateway, a corporate proxy that terminates for
    /// the vendor. Exact host or a <c>*.suffix</c> wildcard.
    /// </summary>
    public IList<string> LlmHosts { get; } = [];

    /// <summary>
    /// Retrieval hosts — the vector store / knowledge corpus (SEC-09). There is no compiled-in
    /// default because there is no vendor: the corpus is wherever the deployment put it.
    /// </summary>
    public IList<string> RagHosts { get; } = [];

    /// <summary>
    /// Observability hosts — an OTLP collector receiving debate traces (SEC-36).
    /// </summary>
    /// <remarks>
    /// <para>
    /// Needed only when <c>Observability:Tracing:CaptureContent</c> is on. A metadata-only trace
    /// carries no job content and its endpoint is not reported to the egress check at all, so a
    /// deployment that turns tracing on for tokens and latency needs nothing here.
    /// </para>
    /// <para>
    /// No compiled-in default, for the same reason <see cref="RagHosts"/> has none: there is no
    /// vendor. Langfuse Cloud is <c>cloud.langfuse.com</c> or <c>us.cloud.langfuse.com</c>; a
    /// self-hosted instance is wherever it was put. Whichever it is, exporting prompts means
    /// writing the host down where an auditor can read it — which is the point.
    /// </para>
    /// </remarks>
    public IList<string> TelemetryHosts { get; } = [];
}

/// <summary>Builds the effective <see cref="IEgressPolicy"/> for a deployment.</summary>
public static class EgressPolicyLoader
{
    /// <summary>
    /// Vendor defaults plus whatever <c>Security:Egress</c> adds.
    /// </summary>
    /// <remarks>
    /// Read with <see cref="IConfigurationSection.Get{T}()"/> against a section that is
    /// usually absent, which is the normal case: a deployment that only talks to a supported
    /// vendor needs no configuration at all, and gets the vendor list.
    /// </remarks>
    public static IEgressPolicy Load(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var section = configuration.GetSection(EgressOptions.SectionName);
        var options = new EgressOptions();

        // Bound by hand rather than by the binder: the two properties are getter-only
        // collections, which the binder populates only under Bind (not Get<T>) and silently
        // leaves empty otherwise — the exact failure ModelOptionsLoader exists to avoid.
        section.Bind(options);

        var allowed = new List<EgressDestination>(EgressPolicy.VendorDefaults);

        allowed.AddRange(options.LlmHosts
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Select(h => new EgressDestination(h.Trim(), EgressPurpose.Llm,
                $"operator-added via {EgressOptions.SectionName}:LlmHosts")));

        allowed.AddRange(options.RagHosts
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Select(h => new EgressDestination(h.Trim(), EgressPurpose.Rag,
                $"operator-added via {EgressOptions.SectionName}:RagHosts")));

        allowed.AddRange(options.TelemetryHosts
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Select(h => new EgressDestination(h.Trim(), EgressPurpose.Telemetry,
                $"operator-added via {EgressOptions.SectionName}:TelemetryHosts")));

        return new EgressPolicy(allowed);
    }
}
