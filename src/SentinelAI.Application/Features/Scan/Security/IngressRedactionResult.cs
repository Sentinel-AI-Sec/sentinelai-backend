using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Features.Scan.Security;

/// <summary>What one run of the ingress gate did (SEC-33).</summary>
/// <param name="Findings">
/// The set that travels on: every message redacted, plus one high-severity finding for each
/// distinct secret found in an infrastructure artifact.
/// </param>
/// <param name="MessagesRedacted">How many incoming findings had a credential removed.</param>
/// <param name="ArtifactSecrets">How many distinct secrets were found in the artifacts.</param>
/// <param name="ArtifactsScanned">How many artifacts were read.</param>
/// <remarks>
/// The counts are what gets logged. They are deliberately the <em>only</em> thing that can be
/// logged: nothing here carries a credential, a line of source, or a file's contents, so no
/// amount of enthusiastic logging downstream can undo the redaction.
/// </remarks>
public sealed record IngressRedactionResult(
    IReadOnlyList<Finding> Findings,
    int MessagesRedacted,
    int ArtifactSecrets,
    int ArtifactsScanned)
{
    /// <summary>True when the gate found anything at all.</summary>
    public bool FoundSecrets => MessagesRedacted > 0 || ArtifactSecrets > 0;
}
