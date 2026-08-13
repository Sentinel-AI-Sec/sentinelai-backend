using System.Text;
using Microsoft.Extensions.Logging;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Security;

/// <summary>
/// The backend's ingress gate (SEC-33): removes credentials from everything a received bundle
/// contributes to a prompt, and reports the ones it found as findings in their own right.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the backend scans at all, when the runner already did.</b> The runner's Gitleaks
/// pre-scan runs on the customer's machine, under the customer's configuration, and reports its
/// own result. Everything about it is outside our control: it can be skipped, misconfigured,
/// pinned to an old rule set, or simply report <c>passed</c> when it did not run. The bundle
/// even tells us which of those happened — <c>scan_bundles.runner_secret_scan</c> records
/// <c>skipped</c> as faithfully as <c>passed</c>. This gate is what makes the promise hold in
/// every one of those cases, so <b>it never reads that field to decide whether to run</b>. A
/// backstop with a condition on it is not a backstop.
/// </para>
/// <para>
/// <b>Why it runs here.</b> Once a secret reaches a model provider it is in someone else's logs
/// and cannot be recalled — there is no delete for that. So the gate sits before the first thing
/// that could send content anywhere: after normalization, which is where scanner text first
/// exists as findings, and before persistence, the graph, retrieval and the debate. A second,
/// narrower guard sits at the model boundary itself (<see cref="RedactingDebateEngine"/>) for
/// the paths that do not come through here.
/// </para>
/// <para>
/// <b>Why a secret is also a finding.</b> Redaction protects us; it does nothing for the
/// customer, whose credential is still sitting in their repository. Reporting it at severity 4
/// is the half of this ticket that is worth something to them — and it is precisely the class of
/// problem the scanners are weakest at, which the fixture records: Security Code Scan has no
/// hardcoded-secret rule at all, so CODE-04 and CODE-05 go unreported by the toolchain.
/// </para>
/// </remarks>
public sealed class IngressRedactionGate(
    ISecretScanner scanner,
    IBundleStore bundleStore,
    ILogger<IngressRedactionGate> logger)
{
    /// <summary>Hardcoded credentials. The one CWE this gate ever assigns.</summary>
    public const string HardcodedSecretCwe = "CWE-798";

    /// <summary>Top of the 0–4 contract scale: a live credential in a repository is critical.</summary>
    public const int SecretSeverity = 4;

    /// <summary>Everything the runner collected lives under this prefix inside the bundle.</summary>
    private const string GraphInputsPrefix = "graph-inputs/";

    /// <summary>
    /// Redacts the findings, scans the bundle's artifacts, and returns the set that travels on.
    /// </summary>
    /// <remarks>
    /// The incoming findings are mutated in place rather than copied. They are the same objects
    /// the caller is about to persist and hand to the graph stage, and returning redacted copies
    /// while the caller kept the originals is exactly the kind of near-miss that would leave the
    /// unredacted text in the database with every flag saying otherwise.
    /// </remarks>
    public async Task<IngressRedactionResult> ApplyAsync(
        string bundleLocator,
        IReadOnlyList<Finding> findings,
        Guid tenantId,
        Guid scanJobId,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(findings);

        var messagesRedacted = RedactFindingText(findings);
        var (secretFindings, artifactsScanned) =
            await ScanArtifactsAsync(bundleLocator, tenantId, scanJobId, ct);

        var all = new List<Finding>(findings.Count + secretFindings.Count);
        all.AddRange(findings);
        all.AddRange(secretFindings);

        if (messagesRedacted > 0 || secretFindings.Count > 0)
        {
            logger.LogWarning(
                "Ingress gate for scan job {ScanJobId}: redacted {Redacted} finding message(s) and "
                + "found {Secrets} hardcoded secret(s) across {Artifacts} artifact(s)",
                scanJobId, messagesRedacted, secretFindings.Count, artifactsScanned);
        }
        else
        {
            logger.LogInformation(
                "Ingress gate for scan job {ScanJobId}: no secrets in {Findings} finding(s) or "
                + "{Artifacts} artifact(s)", scanJobId, findings.Count, artifactsScanned);
        }

        return new IngressRedactionResult(all, messagesRedacted, secretFindings.Count, artifactsScanned);
    }

    /// <summary>
    /// Redacts each finding's message, flagging the ones that changed.
    /// </summary>
    /// <remarks>
    /// Scanner messages quote the offending line, so a credential in the customer's source
    /// arrives here inside the text of a finding about something else entirely — Trivy
    /// reporting a misconfiguration on the same Dockerfile line that bakes in an API key. That
    /// is the ordinary path by which a secret would otherwise reach a prompt, not an edge case.
    /// </remarks>
    private int RedactFindingText(IReadOnlyList<Finding> findings)
    {
        var redacted = 0;

        foreach (var finding in findings)
        {
            var result = scanner.Scan(finding.Message);
            if (!result.HasSecrets) continue;

            finding.Message = result.Redacted;
            finding.Redacted = true;      // per-finding proof, per the D2 findings table
            redacted++;
        }

        return redacted;
    }

    /// <summary>
    /// Scans the bundle's infrastructure artifacts and raises one finding per distinct secret.
    /// </summary>
    /// <remarks>
    /// <para>
    /// These are the files the runner ships so the backend can rebuild the graph — Terraform,
    /// the Dockerfile, manifests — and they are exactly where hardcoded credentials live: a
    /// <c>password</c> default in a variable block, an <c>ENV</c> line baking a key into an
    /// image. The runner never redacts them, because it is not the runner's job to decide what
    /// our models may see.
    /// </para>
    /// <para>
    /// A failure to read the bundle is logged and swallowed rather than thrown. This gate cannot
    /// be the reason a scan dies: an unreadable bundle is already going to fail loudly in the
    /// graph stage, which is where that diagnosis belongs, and a redaction step that turns a
    /// degraded scan into no scan would get switched off.
    /// </para>
    /// </remarks>
    private async Task<(List<Finding> Findings, int ArtifactsScanned)> ScanArtifactsAsync(
        string bundleLocator, Guid tenantId, Guid scanJobId, CancellationToken ct)
    {
        var findings = new List<Finding>();

        if (string.IsNullOrWhiteSpace(bundleLocator))
            return (findings, 0);

        IReadOnlyList<StoredBundleFile> artifacts;
        try
        {
            artifacts = await bundleStore.OpenGraphInputsAsync(bundleLocator, ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex,
                "Could not read the artifacts of scan job {ScanJobId} for the ingress scan; the "
                + "finding text was still redacted", scanJobId);
            return (findings, 0);
        }

        // One finding per (file, line, rule). A key repeated on twenty lines of one file is
        // twenty things to rotate; the same key found twice by two overlapping rules is one.
        var seen = new HashSet<(string Path, int Line, string Rule)>();

        foreach (var artifact in artifacts)
        {
            var path = RepoRelative(artifact.Name);
            var result = scanner.Scan(Decode(artifact.Content));

            foreach (var match in result.Matches)
            {
                if (!seen.Add((path, match.Line, match.RuleId))) continue;

                findings.Add(SecretFinding(path, match, tenantId, scanJobId));
            }
        }

        return (findings, artifacts.Count);
    }

    /// <summary>
    /// The finding raised for one hardcoded credential.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="Finding.Redacted"/> is true even though this finding was never redacted: it
    /// was <em>written</em> redacted, which is the same claim the flag makes — no unredacted
    /// form of this text ever existed.
    /// </para>
    /// <para>
    /// The node reference comes from <see cref="FindingUnifier.NodeRefFor"/> rather than being
    /// built here, so this finding lands on the same node as every other finding about the same
    /// file. Spelling a key by hand is the exact mechanism SEC-03 exists to prevent, and the
    /// consequence would be quiet: a secret finding on an island node, decorating nothing,
    /// seeding no chain.
    /// </para>
    /// </remarks>
    private static Finding SecretFinding(string path, SecretMatch match, Guid tenantId, Guid scanJobId)
    {
        var location = match.Line > 0 ? $"{path}:{match.Line}" : path;

        var finding = new Finding
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenantId,
            ScanJobId = scanJobId,
            SourceTool = ScannerNames.IngressGate,
            Layer = Layer.Infra,
            Severity = SecretSeverity,
            CweId = HardcodedSecretCwe,
            CveId = null,
            CheckId = match.RuleId,
            Location = location,
            Redacted = true,
            Message =
                $"Hardcoded credential in {location} (rule: {match.RuleId}). The value was removed "
                + "at ingress and never reached a model, but it is still present in the repository "
                + "and should be rotated and moved to a secret store.",
        };

        finding.NodeRef = FindingUnifier.NodeRefFor(finding);
        return finding;
    }

    /// <summary>
    /// Strips the bundle's <c>graph-inputs/</c> prefix so a location reads the way every other
    /// finding's does — repo-relative, which is what the developer has to go and open.
    /// </summary>
    private static string RepoRelative(string bundlePath) =>
        bundlePath.StartsWith(GraphInputsPrefix, StringComparison.OrdinalIgnoreCase)
            ? bundlePath[GraphInputsPrefix.Length..]
            : bundlePath;

    /// <summary>
    /// Decodes an artifact as UTF-8, tolerating a byte-order mark and invalid bytes.
    /// </summary>
    /// <remarks>
    /// Throwing on malformed input would let one binary file in a bundle stop the gate scanning
    /// the rest — the wrong failure mode entirely. Undecodable bytes become replacement
    /// characters, which no rule matches, so the file simply reports nothing.
    /// </remarks>
    private static string Decode(byte[] content) =>
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false)
            .GetString(content).TrimStart('\uFEFF');
}
