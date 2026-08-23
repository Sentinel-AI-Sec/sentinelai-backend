namespace SentinelAI.Application.Features.Scan.Security;

/// <summary>Why an outbound destination is on the allowlist at all.</summary>
public enum EgressPurpose
{
    /// <summary>Model inference — the debate's provider endpoint.</summary>
    Llm,

    /// <summary>Retrieval — the knowledge corpus / vector store.</summary>
    Rag,

    /// <summary>
    /// Observability — an OTLP collector receiving debate traces (SEC-36).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Only counts as egress when the traces carry content.</b> A metadata-only trace holds
    /// token counts, a tier, a latency and a role: nothing of the customer's. Traces carrying
    /// prompts and completions are a second destination for job content alongside the model
    /// provider, and that is what this purpose exists to make an operator declare.
    /// </para>
    /// <para>
    /// There is no compiled-in default host, deliberately — the same as <see cref="Rag"/>, and
    /// for the same reason: there is no vendor. A collector is wherever the deployment put it,
    /// so exporting prompts means naming the host in <c>Security:Egress:TelemetryHosts</c>,
    /// where an auditor can read it.
    /// </para>
    /// </remarks>
    Telemetry,
}

/// <summary>
/// One host the backend is permitted to talk to while processing a job.
/// </summary>
/// <param name="HostPattern">
/// An exact host (<c>api.anthropic.com</c>) or a single-level wildcard
/// (<c>*.openai.azure.com</c>). Wildcards exist only because Azure OpenAI's host contains the
/// customer's own resource name, so no exact host can be known ahead of time.
/// </param>
/// <param name="Purpose">Which of the two permitted reasons this host serves.</param>
/// <param name="Note">Why it is here, for the operator reading the effective policy in a log.</param>
public sealed record EgressDestination(string HostPattern, EgressPurpose Purpose, string Note)
{
    /// <summary>True when <paramref name="host"/> is this destination.</summary>
    public bool Matches(string host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;

        if (!HostPattern.StartsWith("*.", StringComparison.Ordinal))
            return string.Equals(host, HostPattern, StringComparison.OrdinalIgnoreCase);

        // "*.openai.azure.com" matches "acme.openai.azure.com" but never the bare suffix,
        // and never "evil-openai.azure.com" — the dot is part of the match on purpose.
        var suffix = HostPattern[1..];
        return host.Length > suffix.Length
            && host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// The set of destinations a job is allowed to reach, and the rule for deciding one.
/// </summary>
public interface IEgressPolicy
{
    /// <summary>The effective allowlist. Everything not on it is denied.</summary>
    IReadOnlyList<EgressDestination> Allowed { get; }

    /// <summary>True when this URI may be called during job processing.</summary>
    bool IsAllowed(Uri destination);

    /// <summary>Why this URI is denied, or null when it is allowed.</summary>
    string? DescribeDenial(Uri destination);
}

/// <summary>
/// SEC-34 box 1: the allowlist of endpoints a scan job may reach, and the reasons a URI is
/// refused.
/// </summary>
/// <remarks>
/// <para>
/// <b>Read this before believing anything about "sandboxing".</b> This type is a
/// <em>policy</em>, not a sandbox. It cannot stop a socket. It knows nothing about DNS, raw
/// TCP, or any library that opens its own connection. Real egress restriction is a network
/// namespace, an egress firewall, or a sidecar proxy that denies by default — infrastructure,
/// configured outside this repository, and none of it exists yet. What is enforced today is
/// stated exactly in <c>docs/Sandboxed_Processing.md</c>; the short version is: a scan job is
/// not accepted while the process is configured to send prompts to a host that is not on this
/// list, and that check runs on the ingest path. Anything beyond that is unenforced.
/// </para>
/// <para>
/// <b>Why the allowlist is compiled in rather than derived from configuration.</b> The
/// obvious implementation — build the allowlist from the endpoints the app is configured to
/// call — produces an assertion that cannot fail, which is the exact defect five audits of
/// this project keep finding. The list below is fixed: the vendors the provider abstraction
/// can actually speak to. An operator who repoints <c>SentinelAI:Models:Endpoint</c> at
/// somewhere else is refused, and that is the whole point of the check.
/// </para>
/// <para>
/// <b>Why "never used to train a model" shows up here.</b> That promise has two halves. The
/// half a vendor owns is contractual — zero-retention terms on the account — and no code of
/// ours can verify it. The half we own is mechanical: the only destinations on this list are
/// inference and retrieval, there is no analytics, telemetry, or dataset host among them, and
/// <see cref="DeniedPathSegments"/> refuses the fine-tuning and file-upload routes on hosts
/// that are otherwise allowed. A customer artifact cannot be submitted for training through a
/// path this policy permits.
/// </para>
/// </remarks>
public sealed class EgressPolicy : IEgressPolicy
{
    /// <summary>
    /// The vendors <c>ChatClientFactory</c> can speak to, and nothing else.
    /// </summary>
    /// <remarks>
    /// <c>Scripted</c> — the default provider — is absent by design: it is offline, makes no
    /// call, and needs no destination. A deployment running Scripted therefore has an empty
    /// set of configured endpoints and passes trivially, which is correct rather than lax.
    /// </remarks>
    public static readonly IReadOnlyList<EgressDestination> VendorDefaults =
    [
        new("api.openai.com", EgressPurpose.Llm, "OpenAI inference"),
        new("*.openai.azure.com", EgressPurpose.Llm, "Azure OpenAI — host carries the customer's resource name"),
        new("api.anthropic.com", EgressPurpose.Llm, "Anthropic inference (OpenAI-compatible gateway)"),
        new("integrate.api.nvidia.com", EgressPurpose.Llm, "NVIDIA NIM inference"),
    ];

    /// <summary>
    /// Routes refused even on an allowed host, because they exist to hand a provider a corpus
    /// rather than to answer a question.
    /// </summary>
    /// <remarks>
    /// Deliberately a denylist, not an allowlist of inference routes. An allowlist of paths
    /// would have to track every SDK's URL shape — Azure alone spells inference as
    /// <c>/openai/deployments/{name}/chat/completions</c> and has changed it twice — and the
    /// failure mode of getting it wrong is a broken debate, whereas the failure mode here is a
    /// route we forgot to name. Neither is free; this one fails towards working software and
    /// still closes the routes that would move an artifact into a training set.
    /// </remarks>
    public static readonly IReadOnlyList<string> DeniedPathSegments =
    [
        "/fine_tun", "/fine-tun", "/finetun", "/training", "/train", "/datasets", "/uploads",
    ];

    public EgressPolicy(IEnumerable<EgressDestination> allowed)
    {
        ArgumentNullException.ThrowIfNull(allowed);
        Allowed = [.. allowed];
    }

    /// <summary>The compiled-in vendor list with no operator additions.</summary>
    public static EgressPolicy Default { get; } = new(VendorDefaults);

    public IReadOnlyList<EgressDestination> Allowed { get; }

    public bool IsAllowed(Uri destination) => DescribeDenial(destination) is null;

    public string? DescribeDenial(Uri destination)
    {
        ArgumentNullException.ThrowIfNull(destination);

        if (!destination.IsAbsoluteUri)
            return $"'{destination}' is not an absolute URI, so its host cannot be checked";

        // Plaintext to an allowed host is still the prompt in the clear on someone's network.
        // Loopback is exempt because a locally hosted vector store on 127.0.0.1 never leaves
        // the machine, and forcing TLS on it would only push operators to disable the check.
        if (!destination.IsLoopback && !string.Equals(destination.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            return $"'{destination}' is not https; job content may only leave over TLS";

        var match = Allowed.FirstOrDefault(d => d.Matches(destination.Host));
        if (match is null)
            return $"host '{destination.Host}' is not on the egress allowlist";

        var path = destination.AbsolutePath;
        var denied = DeniedPathSegments.FirstOrDefault(
            s => path.Contains(s, StringComparison.OrdinalIgnoreCase));

        return denied is null
            ? null
            : $"'{destination.Host}{path}' is a '{denied}' route — received artifacts are never "
              + "submitted for training or bulk upload, so this route is refused even on an "
              + "allowed host";
    }
}
