using Microsoft.Extensions.Configuration;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Infrastructure.Observability;
using SentinelAI.Infrastructure.Security;

namespace SentinelAI.Infrastructure.Tests.Security;

/// <summary>
/// SEC-36 meeting SEC-34: a trace that carries prompts is a second destination for job content,
/// and goes in front of the same egress check the model provider passes.
/// </summary>
/// <remarks>
/// <para>
/// <b>The distinction under test is between two kinds of trace, not between tracing and not.</b>
/// A metadata-only trace holds a token count, a tier, a latency and a role name — none of it the
/// customer's — and its endpoint is not reported to the egress check at all. A trace carrying
/// prompts and completions is the customer's infrastructure description leaving the process a
/// second time, to a host the model-provider allowlist has never heard of.
/// </para>
/// <para>
/// Getting this backwards in either direction is a real cost. Requiring an allowlist entry for
/// metadata pushes operators to leave observability off, or to add a blanket host and mean
/// nothing by it. Not requiring one for content means prompts leave for a destination no check
/// ever looked at — which is the failure the whole egress story exists to prevent.
/// </para>
/// </remarks>
public class TelemetryEgressTests
{
    private const string Collector = "https://cloud.langfuse.com/api/public/otel/v1/traces";

    private static IConfiguration Config(params (string Key, string Value)[] settings) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(settings.ToDictionary(s => s.Key, s => (string?)s.Value))
            .Build();

    private static (string, string) Endpoint(string value) =>
        ($"{TracingOptions.SectionName}:OtlpEndpoint", value);

    private static (string, string) CaptureContent(bool value) =>
        ($"{TracingOptions.SectionName}:CaptureContent", value.ToString());

    // ---- what counts as egress ---------------------------------------------------------

    /// <summary>
    /// Metadata-only tracing does not put the collector in front of the egress check.
    /// </summary>
    [Fact]
    public void A_metadata_only_collector_is_not_reported_as_a_job_content_destination()
    {
        var catalog = new ConfiguredOutboundEndpoints(
            Config(Endpoint(Collector), CaptureContent(false)));

        Assert.DoesNotContain(catalog.Endpoints, e => e.Purpose == EgressPurpose.Telemetry);
    }

    /// <summary>
    /// Turning content capture on puts it there, named by the setting that did it.
    /// </summary>
    /// <remarks>
    /// The name matters as much as the entry: the refusal message quotes it, so an operator
    /// reading a 503 is told which setting to look at rather than being handed a bare host.
    /// </remarks>
    [Fact]
    public void A_content_capturing_collector_is_reported_as_a_job_content_destination()
    {
        var catalog = new ConfiguredOutboundEndpoints(
            Config(Endpoint(Collector), CaptureContent(true)));

        var telemetry = Assert.Single(catalog.Endpoints, e => e.Purpose == EgressPurpose.Telemetry);

        Assert.Equal($"{TracingOptions.SectionName}:OtlpEndpoint", telemetry.Name);
        Assert.Equal(new Uri(Collector), telemetry.Uri);
    }

    /// <summary>Content capture with no collector configured exports nothing and reports nothing.</summary>
    [Fact]
    public void Content_capture_without_a_collector_reports_nothing()
    {
        var catalog = new ConfiguredOutboundEndpoints(Config(Endpoint(""), CaptureContent(true)));

        Assert.DoesNotContain(catalog.Endpoints, e => e.Purpose == EgressPurpose.Telemetry);
    }

    // ---- what the policy then does with it ------------------------------------------------

    /// <summary>
    /// An undeclared collector is denied, so the deployment stops accepting scan jobs.
    /// </summary>
    /// <remarks>
    /// There is no compiled-in telemetry host, deliberately — the same as the vector store, and
    /// for the same reason: there is no vendor. So switching content capture on without naming
    /// the host is refused, which is the outcome that makes the decision deliberate.
    /// </remarks>
    [Fact]
    public void An_undeclared_collector_is_denied_by_the_default_policy()
    {
        var policy = EgressPolicyLoader.Load(Config(Endpoint(Collector), CaptureContent(true)));

        Assert.Contains("not on the egress allowlist", policy.DescribeDenial(new Uri(Collector)));
    }

    /// <summary>Naming the host in <c>Security:Egress:TelemetryHosts</c> allows it.</summary>
    [Fact]
    public void A_collector_named_in_the_configuration_is_allowed()
    {
        var policy = EgressPolicyLoader.Load(Config(
            ($"{EgressOptions.SectionName}:TelemetryHosts:0", "cloud.langfuse.com")));

        Assert.Null(policy.DescribeDenial(new Uri(Collector)));

        var destination = Assert.Single(policy.Allowed, d => d.Purpose == EgressPurpose.Telemetry);
        Assert.Contains("TelemetryHosts", destination.Note);
    }

    /// <summary>
    /// A self-hosted collector still has to be https, or reachable only on loopback.
    /// </summary>
    /// <remarks>
    /// The prompts are the whole point of capturing content; sending them in the clear to an
    /// internal collector puts them on somebody's network. Loopback is exempt for the same
    /// reason a local vector store is: it never leaves the machine.
    /// </remarks>
    [Theory]
    [InlineData("http://otel.internal.example.com/v1/traces", "is not https")]
    [InlineData("http://127.0.0.1:4318/v1/traces", null)]
    public void A_self_hosted_collector_obeys_the_same_transport_rule(string uri, string? expected)
    {
        var policy = EgressPolicyLoader.Load(Config(
            ($"{EgressOptions.SectionName}:TelemetryHosts:0", "otel.internal.example.com"),
            ($"{EgressOptions.SectionName}:TelemetryHosts:1", "127.0.0.1")));

        var denial = policy.DescribeDenial(new Uri(uri));

        if (expected is null) Assert.Null(denial);
        else Assert.Contains(expected, denial);
    }

    // ---- the loader ------------------------------------------------------------------------

    /// <summary>
    /// Langfuse's key pair becomes the Basic header its OTLP endpoint expects.
    /// </summary>
    /// <remarks>
    /// Composed here rather than left to the operator because base64-encoding a colon-joined
    /// pair by hand is the step people get wrong, and its failure mode is a 401 from a collector
    /// nobody is watching.
    /// </remarks>
    [Fact]
    public void Langfuse_keys_compose_into_a_basic_authorization_header()
    {
        var options = TracingOptionsLoader.Load(Config(
            Endpoint(Collector),
            ($"{TracingOptions.SectionName}:Langfuse:PublicKey", "pk-lf-public"),
            ($"{TracingOptions.SectionName}:Langfuse:SecretKey", "sk-lf-secret")));

        var expected = Convert.ToBase64String("pk-lf-public:sk-lf-secret"u8.ToArray());

        Assert.Equal($"Authorization=Basic {expected}", options.ComposeHeaders());
    }

    /// <summary>Half a key pair composes no header rather than a broken one.</summary>
    [Fact]
    public void An_incomplete_langfuse_key_pair_composes_no_header()
    {
        var options = TracingOptionsLoader.Load(Config(
            Endpoint(Collector),
            ($"{TracingOptions.SectionName}:Langfuse:PublicKey", "pk-lf-public")));

        Assert.Null(options.ComposeHeaders());
    }

    /// <summary>
    /// An operator's own header wins over the composed Langfuse one.
    /// </summary>
    /// <remarks>
    /// A deployment fronted by its own gateway authenticates to the gateway, not to Langfuse.
    /// The more specific setting is the one that should take effect, so it is ordered last.
    /// </remarks>
    [Fact]
    public void An_operator_header_is_kept_alongside_the_langfuse_one()
    {
        var options = TracingOptionsLoader.Load(Config(
            Endpoint(Collector),
            ($"{TracingOptions.SectionName}:Langfuse:PublicKey", "pk"),
            ($"{TracingOptions.SectionName}:Langfuse:SecretKey", "sk"),
            ($"{TracingOptions.SectionName}:Headers", "X-Scope-OrgID=sentinelai")));

        var headers = options.ComposeHeaders();

        Assert.StartsWith("Authorization=Basic ", headers);
        Assert.EndsWith(",X-Scope-OrgID=sentinelai", headers);
    }

    /// <summary>
    /// The shipped default is off, and off means nothing is exported.
    /// </summary>
    /// <remarks>
    /// Asserted against an empty configuration rather than against <c>appsettings.json</c>: what
    /// matters is that a deployment which says nothing gets tracing off, whatever any file
    /// happens to contain.
    /// </remarks>
    [Fact]
    public void An_unconfigured_deployment_has_tracing_off_and_captures_nothing()
    {
        var options = TracingOptionsLoader.Load(Config());

        Assert.False(options.IsEnabled);
        Assert.False(options.CaptureContent);
        Assert.Null(options.ComposeHeaders());
    }
}
