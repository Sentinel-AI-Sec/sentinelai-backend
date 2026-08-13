namespace SentinelAI.Domain.Abstractions;

/// <summary>
/// Finds credentials in text and hands back the text with them removed (SEC-33).
/// </summary>
/// <remarks>
/// <para>
/// A port rather than a helper because detection is pattern work that belongs in
/// Infrastructure, and because the ingress gate is a policy the Application layer states while
/// staying free of how a secret is recognized.
/// </para>
/// <para>
/// <b>Note what the contract does not offer: a way to read the secret back.</b> There is one
/// method, it returns the redacted text and the positions, and <see cref="SecretMatch"/> holds
/// no value. A scanner that returned the plaintext it found would be one careless log line away
/// from writing every customer credential into our own telemetry — the precise failure this
/// ticket exists to prevent, reintroduced by the component meant to prevent it. Redaction and
/// detection are one call for the same reason: a caller cannot detect and then forget to
/// redact.
/// </para>
/// </remarks>
public interface ISecretScanner
{
    /// <summary>Scans <paramref name="text"/>, returning it redacted alongside what was found.</summary>
    SecretScanResult Scan(string? text);
}

/// <summary>One credential found in text, described without quoting it.</summary>
/// <param name="RuleId">Which pattern matched, e.g. <c>aws-access-key-id</c>. Safe to log.</param>
/// <param name="Line">1-based line the match started on. 0 when the text has no line structure.</param>
public sealed record SecretMatch(string RuleId, int Line);

/// <summary>The redacted text and the matches that produced it — always in agreement.</summary>
/// <param name="Redacted">
/// The input with every match replaced by a placeholder naming the rule that fired. Identical to
/// the input when nothing matched.
/// </param>
public sealed record SecretScanResult(string Redacted, IReadOnlyList<SecretMatch> Matches)
{
    public bool HasSecrets => Matches.Count > 0;

    /// <summary>The result for text that held nothing.</summary>
    public static SecretScanResult Clean(string? text) => new(text ?? string.Empty, []);
}
