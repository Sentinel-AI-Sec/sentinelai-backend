using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions;

namespace SentinelAI.Infrastructure.Knowledge;

/// <summary>
/// A deliberately dumb <see cref="IKnowledgeRetriever"/> that answers from a small in-memory
/// map of CWE and CVE ids. It exists so the walking skeleton (SEC-45) can cross the retrieval
/// seam before Qdrant is stood up (SEC-09).
/// </summary>
/// <remarks>
/// <para>
/// <b>This is not a search.</b> It matches a linking key that appears in the query and returns
/// canned text, or returns nothing. There is no ranking, no embedding, no corpus. The point is
/// that the <em>seam</em> — what the pipeline asks for and what shape comes back — is fixed and
/// tested now, so the day the Qdrant retriever lands it is a registration change and nothing
/// upstream moves.
/// </para>
/// <para>
/// It logs a warning on every call rather than staying quiet. A stub retriever that silently
/// answers looks exactly like a real one returning thin results, and the failure it would cause
/// — a report citing knowledge that was never retrieved — is the kind that reads as plausible.
/// Anyone running a real scan against this needs to see it in the log.
/// </para>
/// <para>
/// Returning an empty list for an unknown key is deliberate and is the honest answer: the
/// corpus does not have it. Callers must already handle empty, because the real retriever will
/// return empty too.
/// </para>
/// </remarks>
public sealed class SeedKnowledgeRetriever(ILogger<SeedKnowledgeRetriever> logger) : IKnowledgeRetriever
{
    /// <summary>The collection names SEC-09 will create. Used here only to tag what came back.</summary>
    public const string Offense = "offense";
    public const string Defense = "defense";

    /// <summary>
    /// Linking key → one chunk per collection. Keyed on the id rather than on words, because an
    /// exact id match is the one retrieval behaviour that will survive into the real corpus
    /// unchanged (SEC-10 pins exact CVE/CWE lookups as a separate path from meaning-based
    /// search).
    /// </summary>
    private static readonly Dictionary<string, (string Offense, string Defense)> Chunks =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["CWE-502"] = (
                "ATT&CK T1059 — Command and Scripting Interpreter. Deserializing untrusted data lets an "
                + "attacker choose the type that gets constructed, turning a data channel into code execution. "
                + "CAPEC-586 (Object Injection) is the matching attack pattern.",
                "OWASP A08:2021 — Software and Data Integrity Failures. Do not deserialize untrusted input. "
                + "Where it is unavoidable, bind to an allow-list of expected types and never resolve types "
                + "from the payload itself."),
            ["CWE-89"] = (
                "ATT&CK T1190 — Exploit Public-Facing Application. SQL injection reaches the data store "
                + "directly and is commonly the first hop of a chain into customer data.",
                "OWASP A03:2021 — Injection. Use parameterised queries; string concatenation into SQL is the "
                + "defect itself, not a style issue."),
            ["CWE-732"] = (
                "ATT&CK T1078 — Valid Accounts. An over-permissive IAM policy lets a compromised workload "
                + "reach resources its function never required, which is what turns one finding into a chain.",
                "OWASP A01:2021 — Broken Access Control. Grant least privilege and scope resource ARNs; a "
                + "wildcard action is an unbounded blast radius."),
            ["CWE-284"] = (
                "ATT&CK T1530 — Data from Cloud Storage. Improper access control on a bucket is the crown-jewel "
                + "step: the point where a chain stops being theoretical.",
                "OWASP A01:2021 — Broken Access Control. Enable public access blocks and prefer explicit deny."),
        };

    public Task<IReadOnlyList<string>> RetrieveAsync(
        string query, string collection, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        logger.LogWarning(
            "SeedKnowledgeRetriever answered a retrieval for {Collection} from canned data. "
            + "This is the SEC-45 walking-skeleton stub, not a corpus — replace it with the "
            + "Qdrant retriever (SEC-09) before any result is shown to a user",
            collection);

        var key = Chunks.Keys.FirstOrDefault(k => query.Contains(k, StringComparison.OrdinalIgnoreCase));
        if (key is null)
            return Task.FromResult<IReadOnlyList<string>>([]);

        var (offense, defense) = Chunks[key];
        var chunk = string.Equals(collection, Defense, StringComparison.OrdinalIgnoreCase) ? defense : offense;

        return Task.FromResult<IReadOnlyList<string>>([$"[{key}] {chunk}"]);
    }

    /// <summary>The linking keys this stub can answer for — used by tests and diagnostics.</summary>
    public static IReadOnlyCollection<string> KnownKeys => Chunks.Keys;
}
