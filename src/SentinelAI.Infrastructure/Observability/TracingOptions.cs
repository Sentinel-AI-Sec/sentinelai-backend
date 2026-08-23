using System.Text;
using Microsoft.Extensions.Configuration;

namespace SentinelAI.Infrastructure.Observability;

/// <summary>
/// Langfuse's OTLP credentials. A public/secret key pair, exchanged for an HTTP Basic header.
/// </summary>
/// <remarks>
/// Langfuse authenticates its OTLP endpoint with Basic auth over the two keys it issues, rather
/// than with a bearer token. Composing the header here means a deployment supplies the two keys
/// it was given instead of base64-encoding them by hand — which is the step people get wrong,
/// and whose failure mode is a 401 from a collector nobody is watching.
/// </remarks>
public sealed class LangfuseOptions
{
    /// <summary>The <c>pk-lf-…</c> key. Not a secret on its own; useless without the other.</summary>
    public string? PublicKey { get; set; }

    /// <summary>The <c>sk-lf-…</c> key. A credential — supply it from the environment or Key Vault.</summary>
    public string? SecretKey { get; set; }

    /// <summary>True when both halves are present, which is the only useful state.</summary>
    public bool IsComplete =>
        !string.IsNullOrWhiteSpace(PublicKey) && !string.IsNullOrWhiteSpace(SecretKey);
}

/// <summary>
/// SEC-36: where debate traces go, and whether they carry the prompts and completions.
/// </summary>
/// <remarks>
/// <para>
/// <b>Unconfigured is the default and is a complete no-op.</b> No exporter is registered, no
/// listener subscribes, and <c>ActivitySource.StartActivity</c> returns null — so the
/// instrumentation costs a null check per turn and nothing else. That matters for the same
/// reason the <c>Scripted</c> provider is the default: a fresh clone and a CI run must work with
/// no credentials and no collector.
/// </para>
/// <para>
/// <b><see cref="CaptureContent"/> is separate from being enabled, and defaults off.</b> Turning
/// tracing on gives tokens, cost, tier, latency and outcome — everything SEC-36 asks for except
/// replay. Replay needs the prompts and completions themselves, and those are customer material:
/// exporting them makes the collector a second destination for job content, alongside the model
/// provider. That is a deliberate decision an operator should make explicitly rather than
/// inherit from switching on observability, so it has its own switch — and, because it is real
/// egress, the endpoint then has to be on the egress allowlist. See
/// <c>ConfiguredOutboundEndpoints</c>.
/// </para>
/// </remarks>
public sealed class TracingOptions
{
    public const string SectionName = "Observability:Tracing";

    /// <summary>
    /// OTLP collector endpoint. Empty disables tracing entirely.
    /// </summary>
    /// <remarks>
    /// Langfuse Cloud is <c>https://cloud.langfuse.com/api/public/otel/v1/traces</c> (or the
    /// <c>us.</c> host); a self-hosted instance or a local collector is whatever the deployment
    /// runs. The exporter uses HTTP/protobuf, so this is the full traces path rather than a
    /// bare gRPC host.
    /// </remarks>
    public string? OtlpEndpoint { get; set; }

    /// <summary>
    /// Extra OTLP headers, in the wire format <c>key=value,key2=value2</c>.
    /// </summary>
    /// <remarks>
    /// For collectors that authenticate with something other than Langfuse's key pair. Composed
    /// with the Langfuse header rather than replacing it, so a deployment behind a gateway can
    /// add its own header without losing authentication.
    /// </remarks>
    public string? Headers { get; set; }

    /// <summary>The <c>service.name</c> resource attribute traces are grouped under.</summary>
    public string ServiceName { get; set; } = "sentinelai-backend";

    /// <summary>
    /// Whether prompts and completions are put on the spans, making the debate replayable.
    /// </summary>
    /// <remarks>
    /// Off by default. See the type's remarks: this is a second egress destination for job
    /// content, not a verbosity setting.
    /// </remarks>
    public bool CaptureContent { get; set; }

    /// <summary>Langfuse's key pair, when Langfuse is the collector.</summary>
    public LangfuseOptions Langfuse { get; } = new();

    /// <summary>True when an endpoint has been named. Nothing is exported otherwise.</summary>
    public bool IsEnabled => !string.IsNullOrWhiteSpace(OtlpEndpoint);

    /// <summary>
    /// The <c>OTEL_EXPORTER_OTLP_HEADERS</c>-shaped string the exporter is configured with,
    /// or null when there is nothing to send.
    /// </summary>
    /// <remarks>
    /// The Langfuse Basic header is prepended rather than appended so an operator-supplied
    /// <c>Authorization</c> in <see cref="Headers"/> wins — a deployment fronted by its own
    /// gateway may need to authenticate to the gateway instead, and the more specific setting
    /// should be the one that takes effect.
    /// </remarks>
    public string? ComposeHeaders()
    {
        var parts = new List<string>();

        if (Langfuse.IsComplete)
        {
            var basic = Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{Langfuse.PublicKey!.Trim()}:{Langfuse.SecretKey!.Trim()}"));

            parts.Add($"Authorization=Basic {basic}");
        }

        if (!string.IsNullOrWhiteSpace(Headers)) parts.Add(Headers.Trim());

        return parts.Count == 0 ? null : string.Join(",", parts);
    }
}

/// <summary>Reads <see cref="TracingOptions"/> from configuration.</summary>
/// <remarks>
/// A loader rather than <c>services.Configure</c> for the same reason
/// <c>ModelOptionsLoader</c> is one: the value is needed at <em>registration</em> time — whether
/// to add an exporter at all is a composition decision, not a request-time one — and it is also
/// read by <c>ConfiguredOutboundEndpoints</c>, which is constructed from <c>IConfiguration</c>
/// with no service provider to ask.
/// </remarks>
public static class TracingOptionsLoader
{
    public static TracingOptions Load(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var options = new TracingOptions();

        // Bind rather than Get<T>: Langfuse is a getter-only property, which Get<T> leaves at
        // its default while reporting success — the silent-empty-binding failure this codebase
        // has been bitten by before.
        configuration.GetSection(TracingOptions.SectionName).Bind(options);

        return options;
    }
}
