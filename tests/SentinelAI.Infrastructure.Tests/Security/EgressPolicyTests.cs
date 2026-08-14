using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Infrastructure.Security;

namespace SentinelAI.Infrastructure.Tests.Security;

/// <summary>
/// SEC-34 box 1, at the level it is actually enforced: which destinations the policy permits,
/// and whether a deployment configured to talk to something else is refused work.
/// </summary>
/// <remarks>
/// None of this is a network sandbox and none of these tests claim one. They cover the
/// allowlist rule and the admission decision built on it. What is <em>not</em> covered,
/// because it is not implemented, is interception of an actual outbound call — see
/// <c>docs/Sandboxed_Processing.md</c>.
/// </remarks>
public class EgressPolicyTests
{
    private static EgressAdmission Admission(IEgressPolicy policy, params OutboundEndpoint[] endpoints) =>
        new(policy, new StubCatalog(endpoints), NullLogger<EgressAdmission>.Instance);

    private sealed class StubCatalog(OutboundEndpoint[] endpoints) : IOutboundEndpointCatalog
    {
        public IReadOnlyList<OutboundEndpoint> Endpoints { get; } = endpoints;
    }

    private static OutboundEndpoint Llm(string uri) =>
        new("SentinelAI:Models:Endpoint", new Uri(uri, UriKind.RelativeOrAbsolute), EgressPurpose.Llm);

    // ---- the allowlist rule ------------------------------------------------------------

    [Theory]
    [InlineData("https://api.anthropic.com/v1/chat/completions")]
    [InlineData("https://integrate.api.nvidia.com/v1/chat/completions")]
    [InlineData("https://api.openai.com/v1/chat/completions")]
    [InlineData("https://acme.openai.azure.com/openai/deployments/gpt-4o/chat/completions")]
    public void The_providers_the_factory_can_speak_to_are_allowed(string uri)
    {
        Assert.True(EgressPolicy.Default.IsAllowed(new Uri(uri)), uri);
    }

    [Theory]
    [InlineData("https://evil.example.com/v1/chat/completions", "not on the egress allowlist")]
    [InlineData("https://telemetry.vendor.io/collect", "not on the egress allowlist")]
    // The wildcard is a suffix match on ".openai.azure.com", so a host that merely ends in
    // the same letters is a different host. Getting this wrong is how allowlists leak.
    [InlineData("https://evil-openai.azure.com/openai/v1/chat", "not on the egress allowlist")]
    [InlineData("https://openai.azure.com/openai/v1/chat", "not on the egress allowlist")]
    public void Anything_else_is_denied(string uri, string expected)
    {
        var denial = EgressPolicy.Default.DescribeDenial(new Uri(uri));

        Assert.NotNull(denial);
        Assert.Contains(expected, denial);
    }

    [Fact]
    public void Plaintext_to_an_allowed_host_is_still_denied()
    {
        var denial = EgressPolicy.Default.DescribeDenial(new Uri("http://api.anthropic.com/v1/messages"));

        Assert.NotNull(denial);
        Assert.Contains("not https", denial);
    }

    /// <summary>
    /// The mechanical half of "received artifacts are never used to train any model": the
    /// routes that would hand a provider a corpus are refused even on a permitted host.
    /// </summary>
    [Theory]
    [InlineData("https://api.openai.com/v1/fine_tuning/jobs")]
    [InlineData("https://api.openai.com/v1/uploads")]
    [InlineData("https://api.anthropic.com/v1/datasets")]
    public void Training_and_bulk_upload_routes_are_denied_on_allowed_hosts(string uri)
    {
        var denial = EgressPolicy.Default.DescribeDenial(new Uri(uri));

        Assert.NotNull(denial);
        Assert.Contains("training", denial);
    }

    [Fact]
    public void No_default_destination_exists_for_anything_but_inference()
    {
        // If a non-LLM host ever appears in the compiled-in list, the claim that the only
        // place job content can go is a model provider stops being true.
        Assert.All(EgressPolicy.VendorDefaults, d => Assert.Equal(EgressPurpose.Llm, d.Purpose));
    }

    // ---- the admission decision ---------------------------------------------------------

    [Fact]
    public void A_deployment_with_no_configured_endpoint_is_admitted()
    {
        // Scripted, and every test in this suite. Stated as its own case so the passing
        // result below is distinguishable from a check that passes unconditionally.
        Assert.Null(Admission(EgressPolicy.Default).Describe());
    }

    [Fact]
    public void A_deployment_pointed_at_an_allowed_vendor_is_admitted()
    {
        Assert.Null(Admission(EgressPolicy.Default, Llm("https://api.anthropic.com/v1")).Describe());
    }

    [Fact]
    public void A_deployment_pointed_off_the_allowlist_is_refused_and_the_host_is_named()
    {
        var problem = Admission(EgressPolicy.Default, Llm("https://evil.example.com/v1")).Describe();

        Assert.NotNull(problem);
        Assert.Contains("evil.example.com", problem);
        Assert.Contains("SentinelAI:Models:Endpoint", problem);
    }

    [Fact]
    public void A_malformed_endpoint_is_refused_rather_than_ignored()
    {
        // A typo that fails to parse must not become an empty catalog and a clean pass.
        var problem = Admission(EgressPolicy.Default, Llm("api.anthropic.com/v1")).Describe();

        Assert.NotNull(problem);
        Assert.Contains("not an absolute URI", problem);
    }

    // ---- configuration ------------------------------------------------------------------

    [Fact]
    public void With_no_configuration_the_policy_is_the_vendor_list()
    {
        var policy = EgressPolicyLoader.Load(new ConfigurationBuilder().Build());

        Assert.Equal(EgressPolicy.VendorDefaults.Count, policy.Allowed.Count);
    }

    [Fact]
    public void An_operator_can_add_a_host_but_the_vendor_list_is_never_removed()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Security:Egress:LlmHosts:0"] = "llm.internal.acme.example",
                ["Security:Egress:RagHosts:0"] = "qdrant.internal.acme.example",
            })
            .Build();

        var policy = EgressPolicyLoader.Load(configuration);

        Assert.True(policy.IsAllowed(new Uri("https://llm.internal.acme.example/v1/chat/completions")));
        Assert.True(policy.IsAllowed(new Uri("https://qdrant.internal.acme.example/collections/x/points/search")));

        // No configuration key removes a vendor default, and none switches the check off.
        Assert.True(policy.IsAllowed(new Uri("https://api.anthropic.com/v1/messages")));
        Assert.False(policy.IsAllowed(new Uri("https://evil.example.com/v1")));
    }

    [Fact]
    public void A_scripted_deployment_configures_no_outbound_endpoint_at_all()
    {
        // The default appsettings shape. Its catalog is empty, which is why the suite's
        // 476 existing tests are unaffected by the admission check.
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SentinelAI:Models:Provider"] = "Scripted",
            })
            .Build();

        Assert.Empty(new ConfiguredOutboundEndpoints(configuration).Endpoints);
    }

    [Fact]
    public void A_configured_endpoint_and_a_per_agent_override_are_both_reported()
    {
        // The per-agent override is the one a check that only read the shared endpoint would
        // miss — and it is the one an attacker with config access would set.
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["SentinelAI:Models:Provider"] = "Nim",
                ["SentinelAI:Models:Endpoint"] = "https://integrate.api.nvidia.com/v1",
                ["SentinelAI:Models:Agents:Red:Endpoint"] = "https://exfil.example.com/v1",
            })
            .Build();

        var catalog = new ConfiguredOutboundEndpoints(configuration);

        Assert.Equal(2, catalog.Endpoints.Count);

        var problem = new EgressAdmission(
            EgressPolicyLoader.Load(configuration), catalog, NullLogger<EgressAdmission>.Instance)
            .Describe();

        Assert.NotNull(problem);
        Assert.Contains("exfil.example.com", problem);
        Assert.Contains("Agents:Red:Endpoint", problem);
    }
}
