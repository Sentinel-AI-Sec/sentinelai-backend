using System.Text;
using System.Text.RegularExpressions;
using SentinelAI.Domain.Abstractions;

namespace SentinelAI.Infrastructure.Security;

/// <summary>
/// The pattern-based <see cref="ISecretScanner"/> behind the ingress gate (SEC-33).
/// </summary>
/// <remarks>
/// <para>
/// Two families of rule, and the split matters. <b>Shaped</b> rules match credentials that
/// announce themselves — an AWS key id, a PEM header, a JWT — and are near zero false positive
/// because the shape belongs to the issuer. <b>Assignment</b> rules match a value only because
/// of the word next to it (<c>api_key = "…"</c>), which is how most hardcoded secrets actually
/// appear and also where every false positive comes from.
/// </para>
/// <para>
/// A false positive costs a redacted word in a prompt. A false negative costs a customer
/// credential sitting in a third-party model provider's logs, permanently, with no way to
/// recall it. The rules are tuned for that asymmetry: an ambiguous value gets redacted.
/// </para>
/// <para>
/// Deliberately <em>not</em> Gitleaks, and sharing no configuration with it. This gate has to
/// hold when the runner's pre-scan was skipped, misconfigured, or wrong, so a backstop that
/// fails the same way as the thing it backs up would be no backstop at all. Both are blunt on
/// purpose and neither is the last word: the runner's job is to stop secrets leaving the
/// customer, ours is to stop them reaching a model.
/// </para>
/// </remarks>
public sealed partial class RegexSecretScanner : ISecretScanner
{
    private static readonly (string RuleId, Regex Pattern)[] Rules =
    [
        // ---- Shaped: the issuer's own format, effectively unambiguous -------------------
        ("private-key",                PrivateKey()),
        ("aws-access-key-id",          AwsAccessKeyId()),
        ("github-token",               GitHubToken()),
        ("slack-token",                SlackToken()),
        ("google-api-key",             GoogleApiKey()),
        ("jwt",                        Jwt()),
        ("url-embedded-password",      UrlEmbeddedPassword()),

        // ---- Assignment: a value a neighbouring word says is a credential ---------------
        ("aws-secret-access-key",      AwsSecretAccessKey()),
        ("connection-string-password", ConnectionStringPassword()),
        ("bearer-token",               BearerToken()),
        ("assigned-secret",            AssignedSecret()),
        ("terraform-variable-default", TerraformVariableDefault()),
    ];

    /// <summary>
    /// Values that look like credentials only because a template has not been filled in.
    /// </summary>
    /// <remarks>
    /// Terraform interpolation is the load-bearing case: <c>password = var.db_password</c> and
    /// <c>= "${var.db_password}"</c> appear in almost every real <c>.tf</c> file, and without
    /// this exclusion every bundle would arrive carrying dozens of "hardcoded secret" findings
    /// that are in fact evidence the author did the right thing. A gate whose output is mostly
    /// noise gets ignored, which is a security failure with extra steps.
    /// </remarks>
    private static readonly Regex Placeholder = PlaceholderPattern();

    public SecretScanResult Scan(string? text)
    {
        if (string.IsNullOrEmpty(text)) return SecretScanResult.Clean(text);

        // Every rule runs against the original text and the spans are collected first, then
        // applied in one rewrite. Rules legitimately overlap — a URL password is also an
        // assigned secret — and editing the text while still matching against it would shift
        // every later index by the length difference of the placeholder.
        var spans = new List<(int Start, int Length, string RuleId)>();

        foreach (var (ruleId, pattern) in Rules)
        {
            MatchCollection matches;
            try
            {
                matches = pattern.Matches(text);
            }
            catch (RegexMatchTimeoutException)
            {
                // A timeout is not "clean". Fail closed and drop the whole text rather than
                // forward content we were unable to finish scanning.
                return new SecretScanResult(
                    $"[REDACTED:scan-timeout] ({text.Length} characters could not be scanned in time)",
                    [new SecretMatch("scan-timeout", 0)]);
            }

            foreach (Match match in matches)
            {
                // A rule that needs surrounding context to find its value captures it as
                // "secret"; without that group the whole match is the credential.
                var captured = match.Groups["secret"].Success ? match.Groups["secret"] : (Capture)match;
                if (captured.Length == 0) continue;

                if (IsPlaceholder(text.Substring(captured.Index, captured.Length))) continue;

                spans.Add((captured.Index, captured.Length, ruleId));
            }
        }

        return spans.Count == 0 ? SecretScanResult.Clean(text) : Rewrite(text, spans);
    }

    /// <summary>Replaces every span with a placeholder naming the rule, left to right.</summary>
    /// <remarks>
    /// Overlapping spans are merged rather than nested, because two rules firing on one value
    /// is the normal case and redacting it twice would produce
    /// <c>[REDACTED:[REDACTED:jwt]bearer-token]</c> — unreadable, and no longer a reliable
    /// count of how many distinct secrets were present.
    /// </remarks>
    private static SecretScanResult Rewrite(string text, List<(int Start, int Length, string RuleId)> spans)
    {
        // Widest span first at a given start, so the outer match wins and the inner one is
        // swallowed by the cursor rather than producing a second placeholder.
        spans.Sort((a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : b.Length.CompareTo(a.Length));

        var sb = new StringBuilder(text.Length);
        var found = new List<SecretMatch>();
        var multiline = text.Contains('\n');
        var cursor = 0;

        foreach (var (start, length, ruleId) in spans)
        {
            if (start < cursor) continue;   // inside a span that was already redacted

            sb.Append(text, cursor, start - cursor);
            sb.Append("[REDACTED:").Append(ruleId).Append(']');

            found.Add(new SecretMatch(ruleId, multiline ? LineAt(text, start) : 0));
            cursor = start + length;
        }

        sb.Append(text, cursor, text.Length - cursor);

        return new SecretScanResult(sb.ToString(), found);
    }

    private static bool IsPlaceholder(string value) => Placeholder.IsMatch(value.Trim());

    /// <summary>1-based line number of the character at <paramref name="index"/>.</summary>
    private static int LineAt(string text, int index)
    {
        var line = 1;
        for (var i = 0; i < index && i < text.Length; i++)
            if (text[i] == '\n') line++;

        return line;
    }

    // -- Shaped ---------------------------------------------------------------------------
    // Every pattern carries a 2s match timeout: a pathological backtrack on a large artifact
    // must not take the ingest thread with it.

    [GeneratedRegex(@"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", RegexOptions.None, 2000)]
    private static partial Regex PrivateKey();

    [GeneratedRegex(@"\b(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z0-9]{16}\b", RegexOptions.None, 2000)]
    private static partial Regex AwsAccessKeyId();

    [GeneratedRegex(@"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b", RegexOptions.None, 2000)]
    private static partial Regex GitHubToken();

    [GeneratedRegex(@"\bxox[baprs]-[A-Za-z0-9-]{10,}", RegexOptions.None, 2000)]
    private static partial Regex SlackToken();

    [GeneratedRegex(@"\bAIza[0-9A-Za-z_\-]{35}\b", RegexOptions.None, 2000)]
    private static partial Regex GoogleApiKey();

    /// <summary>Three base64url segments: a signed JWT, which by definition carries live claims.</summary>
    [GeneratedRegex(@"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", RegexOptions.None, 2000)]
    private static partial Regex Jwt();

    /// <summary>The password in <c>scheme://user:password@host</c>.</summary>
    [GeneratedRegex(@"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@]+:(?<secret>[^\s@/]{3,})@", RegexOptions.None, 2000)]
    private static partial Regex UrlEmbeddedPassword();

    // -- Assignment -----------------------------------------------------------------------

    [GeneratedRegex(@"(?i)aws[^\n]{0,24}?(?:secret|private)[^\n]{0,24}?[:=]\s*[""']?(?<secret>[A-Za-z0-9/+=]{40})[""']?", RegexOptions.None, 2000)]
    private static partial Regex AwsSecretAccessKey();

    [GeneratedRegex(@"(?i)\b(?:password|pwd)\s*=\s*(?<secret>[^;""'\s,}\]]{4,})", RegexOptions.None, 2000)]
    private static partial Regex ConnectionStringPassword();

    [GeneratedRegex(@"(?i)\bbearer\s+(?<secret>[A-Za-z0-9._\-]{16,})", RegexOptions.None, 2000)]
    private static partial Regex BearerToken();

    /// <summary>
    /// <c>api_key = "…"</c> and its many spellings, including the <c>ENV FOO_API_KEY="…"</c>
    /// form the reference fixture uses to bake its Dockerfile secret (INFRA-07).
    /// </summary>
    /// <remarks>
    /// The 8-character floor is what keeps <c>password = ""</c> and <c>token: no</c> out. The
    /// value stops at whitespace, quotes and separators so only the credential is replaced and
    /// the rest of the line survives — a finding has to stay diagnosable after redaction, or
    /// the developer who has to rotate the key cannot tell which key it was.
    /// </remarks>
    [GeneratedRegex(@"(?i)\b(?:[A-Za-z0-9_\-]*(?:api[_\-]?key|apikey|secret|passwd|password|access[_\-]?key|client[_\-]?secret|auth[_\-]?token|token)|[A-Za-z0-9]+[_\-]key)\b\s*[:=]\s*[""']?(?<secret>[^\s""',;)}\]]{8,})[""']?", RegexOptions.None, 2000)]
    private static partial Regex AssignedSecret();


    /// <summary>
    /// A Terraform variable whose name says credential, carrying a literal default.
    /// </summary>
    /// <remarks>
    /// The assignment rules cannot see this one: the keyword is in the block header and the
    /// value is on a later line next to the neutral word <c>default</c>, so nothing sits beside
    /// the secret to identify it. It is worth a rule of its own because it is the single most
    /// common way a credential ends up committed in Terraform — a variable declared for the
    /// right reason and then given a working value "temporarily".
    /// </remarks>
    [GeneratedRegex(@"(?i)variable\s+""[A-Za-z0-9_\-]*(?:password|passwd|secret|token|api[_\-]?key|[A-Za-z0-9]+[_\-]key)""\s*\{[^}]*?\bdefault\s*=\s*""(?<secret>[^""\n]{6,})""", RegexOptions.None, 2000)]
    private static partial Regex TerraformVariableDefault();
    /// <summary>Template syntax, a Terraform reference, or an obvious unfilled sample value.</summary>
    [GeneratedRegex(@"(?i)^(?:\$\{[^}]*\}?|\{\{[^}]*\}{0,2}|<[^>]*>?|%[a-z_]+%|(?:var|local|data|module|each)\.[a-z0-9_.\-]+|null|none|true|false|x{3,}|\*{3,}|\.{3,}|change[_\-]?me|your[_\-].*|replace[_\-]?me|todo|tbd|example|placeholder|redacted|\[redacted:[a-z\-]+\])$", RegexOptions.None, 2000)]
    private static partial Regex PlaceholderPattern();
}
