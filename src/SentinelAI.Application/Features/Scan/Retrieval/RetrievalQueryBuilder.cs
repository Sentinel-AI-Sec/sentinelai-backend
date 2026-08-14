using System.Text;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>
/// SEC-21: turns one finding into the short natural-language query the knowledge corpus is
/// searched with — its linking identifiers, what kind of thing it is on, and whatever the scanner
/// actually said, with the scanner's own scaffolding removed.
/// </summary>
/// <remarks>
/// <para>
/// <b>What this replaces, and why the old version could not stay.</b> The pipeline used to send
/// <c>"{key} {finding.Message}"</c>. For a Roslyn finding that reads fine; for a Trivy dependency
/// finding the message is six lines of fields — <c>Package:</c>, <c>Installed Version:</c>,
/// <c>Severity: HIGH</c>, <c>Fixed Version:</c>, and a markdown link to the advisory — and every
/// one of those words went into the embedding. The retrieval that comes back is then partly a
/// search for the words "installed version" and "HIGH", which every dependency finding in the
/// scan shares. Retrieval that cannot tell two findings apart is retrieval that adds nothing, and
/// it fails quietly: chunks come back, they are plausible, and nobody can see they are the wrong
/// ones.
/// </para>
/// <para>
/// <b>Identifiers lead.</b> SEC-10 keeps exact CWE/CVE lookup as a separate path from
/// meaning-based search, and the seed retriever matches on an id appearing in the query text. So
/// the id goes first and verbatim. A finding with neither a CWE nor a CVE gets no query at all —
/// see <see cref="Build"/>.
/// </para>
/// <para>
/// <b>What it will not do.</b> It never sends the raw SARIF, the source line, the rule id or the
/// tool name. Those identify the scanner, not the weakness, and the corpus is written about
/// weaknesses; a rule id in the query is a token nothing in the corpus can match, and a file path
/// is a token that matches the wrong things. It is also a second line of defence for the ingress
/// gate (SEC-33): the less scanner-quoted source text leaves this process, the less there is to
/// leak.
/// </para>
/// <para>
/// The stripping rules below are pattern-matching against the field labels these scanners are
/// observed to emit, not a parser for any of their formats. An unrecognised label survives into
/// the query, which is the failure worth having: a stray label costs a little precision, whereas a
/// rule aggressive enough to guarantee no boilerplate would eventually eat a real description and
/// leave a query that is nothing but an id.
/// </para>
/// </remarks>
public sealed class RetrievalQueryBuilder
{
    /// <summary>
    /// The most description words a query carries.
    /// </summary>
    /// <remarks>
    /// A query is a search phrase, not a summary. Past roughly this length the extra words are the
    /// tail of a scanner sentence — remediation advice, a version list — and they pull the
    /// embedding away from the weakness the first clause names.
    /// </remarks>
    public const int MaxDescriptionWords = 20;

    /// <summary>
    /// How many words a description must contribute before it is worth carrying at all.
    /// </summary>
    /// <remarks>
    /// Under this, the message said nothing the identifiers and the subject did not already say —
    /// OSV's <c>"Package 'X@1.0' is vulnerable to 'CVE-…' (also known as 'GHSA-…')"</c> is the
    /// whole pattern: three ids, a coordinate and four connecting words. Dropping it leaves a
    /// shorter, sharper query rather than one that repeats itself.
    /// </remarks>
    public const int MinDescriptionWords = 2;

    /// <summary>
    /// The query for this finding, or null when it carries no CWE and no CVE.
    /// </summary>
    /// <remarks>
    /// Null rather than a description-only query: with no id there is nothing the corpus can be
    /// keyed on, and a query built from prose alone retrieves whatever is nearest in the embedding
    /// space, which is a plausible-looking answer to a question nobody asked. The caller counts
    /// these — a rising count means SEC-15's rule-mapping table has fallen behind the scanners.
    /// </remarks>
    public string? Build(Finding finding)
    {
        ArgumentNullException.ThrowIfNull(finding);

        var keys = LinkingKeys(finding);
        if (keys.Count == 0) return null;

        var (nodeType, subject) = SubjectOf(finding);
        var description = Describe(finding.Message, keys, subject);

        var query = new StringBuilder()
            .AppendJoin(' ', keys)
            .Append(' ')
            .Append(SubjectPhrase(finding.Layer, nodeType, subject));

        if (description.Length > 0) query.Append(": ").Append(description);

        return query.ToString();
    }

    /// <summary>
    /// The ids the corpus can be matched on exactly, CWE first.
    /// </summary>
    /// <remarks>
    /// CWE leads because it names the weakness class, which is what the offensive corpus is
    /// organised by; a CVE names one instance of it and is the narrower key. Both are carried when
    /// both exist — they retrieve different chunks and the query is short enough to afford it.
    /// </remarks>
    private static List<string> LinkingKeys(Finding finding)
    {
        var keys = new List<string>(capacity: 2);

        if (!string.IsNullOrWhiteSpace(finding.CweId)) keys.Add(finding.CweId.Trim());
        if (!string.IsNullOrWhiteSpace(finding.CveId)) keys.Add(finding.CveId.Trim());

        return keys;
    }

    /// <summary>
    /// The thing the finding is about, read out of its canonical node reference.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see cref="Finding.NodeRef"/> rather than <see cref="Finding.Location"/>, because the node
    /// reference is the one subject that survived normalization and is the same string the graph
    /// joins on. A finding whose reference is not canonical yields no subject and the template
    /// degrades to a bare phrase; it is not this class's job to be loud about that, which
    /// <c>GraphSeeder</c> already is.
    /// </para>
    /// <para>
    /// File-derived keys are reduced to the file's own name: the code node for a Roslyn finding is
    /// keyed <c>code:src/orderapp/controllers/orderscontroller.cs</c>, and the directories and the
    /// extension are the repository's filing system, not anything the corpus knows about. Package
    /// keys are left whole — <c>pkg:newtonsoft.json</c> would lose its second half to an extension
    /// rule, and the version in <c>name:version</c> is part of the identifier, so the separator
    /// simply becomes a space.
    /// </para>
    /// </remarks>
    private static (NodeType? NodeType, string Subject) SubjectOf(Finding finding)
    {
        if (!NodeId.TryParse(finding.NodeRef, out var nodeType, out var identifier))
            return (null, string.Empty);

        var subject = nodeType is NodeType.Code or NodeType.Resource ? FileName(identifier) : identifier;

        return (nodeType, subject.Replace(NodeId.Separator, ' ').Trim());
    }

    /// <summary>Source and configuration extensions, so a package name can never lose its tail.</summary>
    private static readonly HashSet<string> FileExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".cs", ".vb", ".fs", ".ts", ".tsx", ".js", ".jsx", ".py", ".java", ".go", ".rb", ".php",
        ".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".xml", ".config", ".dockerfile",
    };

    private static string FileName(string identifier)
    {
        var name = identifier[(identifier.LastIndexOf('/') + 1)..];
        var dot = name.LastIndexOf('.');

        return dot > 0 && FileExtensions.Contains(name[dot..]) ? name[..dot] : name;
    }

    /// <summary>
    /// The per-layer template: how the subject is named to the corpus.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three templates because the three layers are asked three different questions. A dependency
    /// query is about a known vulnerable component and the corpus answers with the advisory and
    /// how it is exploited. A code query is about a weakness in something we wrote, where the
    /// component name is a hint and the weakness class is the search. An infrastructure query is
    /// about a resource being configured in a way that helps an attacker, so it names the kind of
    /// resource — a finding on an IAM role and a finding on a bucket want different chunks even
    /// under the same CWE.
    /// </para>
    /// <para>
    /// The wording is a handful of fixed words per layer, and that is the whole budget. Anything
    /// longer is boilerplate of our own making: a phrase appended to every query in a layer adds
    /// nothing that distinguishes one query in that layer from another.
    /// </para>
    /// </remarks>
    private static string SubjectPhrase(Layer layer, NodeType? nodeType, string subject) => layer switch
    {
        Layer.Dep => Phrase("vulnerable dependency", subject),
        Layer.Code => Phrase("vulnerable code in", subject, bare: "vulnerable code"),
        _ => Phrase($"insecure {ResourceWord(nodeType)}", subject),
    };

    private static string Phrase(string prefix, string subject, string? bare = null) =>
        subject.Length == 0 ? bare ?? prefix : $"{prefix} {subject}";

    /// <summary>
    /// The kind of resource, in the words the corpus uses rather than the node key's prefix.
    /// </summary>
    /// <remarks>
    /// The prefixes are wire format and some are historical — <see cref="NodeType.Resource"/>
    /// spells itself <c>s3</c> for reasons <see cref="NodeTypeExtensions.Prefix"/> records — so
    /// they are the wrong thing to put in a natural-language query. An unknown node type falls
    /// back to a generic word instead of being omitted, because the layer is still known and the
    /// template should not silently lose a term.
    /// </remarks>
    private static string ResourceWord(NodeType? nodeType) => nodeType switch
    {
        NodeType.IamRole => "iam role",
        NodeType.Resource => "cloud data resource",
        NodeType.Task => "deployed workload",
        NodeType.Image => "container image",
        NodeType.Code => "code",
        NodeType.Pkg => "dependency",
        _ => "infrastructure resource",
    };

    /// <summary>
    /// What the scanner said, once its scaffolding, its links and its restatements of the
    /// identifiers are gone. Empty when it said nothing the rest of the query does not.
    /// </summary>
    private static string Describe(string message, List<string> keys, string subject)
    {
        if (string.IsNullOrWhiteSpace(message)) return string.Empty;

        var named = new HashSet<string>(keys, StringComparer.OrdinalIgnoreCase);
        foreach (var word in subject.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            named.Add(word);

        var kept = new List<string>(MaxDescriptionWords);
        var content = 0;

        foreach (var token in Prose(message).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
        {
            if (IsLink(token)) continue;

            var bare = token.Trim(Punctuation).ToLowerInvariant();
            if (bare.Length == 0 || IsRedactionMarker(bare) || AlreadyNamed(bare, named)) continue;

            kept.Add(token);
            if (!Connectives.Contains(bare)) content++;

            if (kept.Count == MaxDescriptionWords) break;
        }

        return content < MinDescriptionWords ? string.Empty : string.Join(' ', kept).Trim(Punctuation);
    }

    /// <summary>
    /// Drops the whole-line fields a scanner message is built from, keeping only prose.
    /// </summary>
    /// <remarks>
    /// Trivy writes one <c>Label: value</c> per line and nothing else, so after this a Trivy
    /// message is empty and the query is its identifiers and its package — which is all Trivy ever
    /// told us. The labels that carry prose lose the label and keep the value, because there the
    /// value <em>is</em> the description. A line whose label is not recognised survives whole; see
    /// the class remarks on why that is the direction to fail in.
    /// </remarks>
    private static string Prose(string message)
    {
        var kept = new List<string>();

        foreach (var raw in message.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;

            var colon = line.IndexOf(':');
            if (colon > 0)
            {
                var label = line[..colon].Trim();

                if (FieldLabels.Contains(label)) continue;
                if (ProseLabels.Contains(label)) line = line[(colon + 1)..].Trim();
            }

            kept.Add(line);
        }

        return string.Join(' ', kept);
    }

    /// <summary>
    /// Line labels observed in the scanners this codebase ingests, whose values are structure
    /// rather than description: the severity word, the fixed-version list, the advisory link.
    /// </summary>
    private static readonly HashSet<string> FieldLabels = new(StringComparer.OrdinalIgnoreCase)
    {
        "package", "package name", "pkgname", "pkgpath", "installed version", "fixed version",
        "fixed versions", "severity", "link", "links", "status", "type", "target", "class",
        "published", "last modified", "cvss", "epss", "reference", "references", "source", "url",
        "rule", "rule id", "ruleid", "id", "vulnerability", "vulnerability id", "cwe", "cve",
    };

    /// <summary>Labels whose value is the description; the label goes, the value stays.</summary>
    private static readonly HashSet<string> ProseLabels = new(StringComparer.OrdinalIgnoreCase)
    {
        "title", "description", "summary", "details", "message",
    };

    /// <summary>
    /// Function words plus the handful of nouns every scanner message is made of. Used only to
    /// decide whether a description said anything — never to remove a word, since removing them
    /// would leave a query that reads like a keyword list rather than a phrase.
    /// </summary>
    private static readonly HashSet<string> Connectives = new(StringComparer.OrdinalIgnoreCase)
    {
        "a", "an", "the", "is", "are", "was", "were", "be", "been", "it", "its", "this", "that",
        "and", "or", "to", "in", "of", "for", "with", "on", "at", "by", "as", "from", "has",
        "have", "also", "known", "no", "not",
        "package", "packages", "version", "versions", "vulnerable", "vulnerability", "vulnerabilities",
    };

    private static readonly char[] Punctuation = ['\'', '"', '(', ')', '[', ']', '{', '}', '<', '>', '.', ',', ';', ':', '!', '?', '*', '`'];

    /// <summary>
    /// Advisory id prefixes. A message's ids are aliases of the one the query already leads with —
    /// OSV lists three spellings of the same advisory — and a query stuffed with aliases retrieves
    /// the alias list instead of the weakness.
    /// </summary>
    private static readonly string[] AdvisoryPrefixes = ["cve-", "cwe-", "ghsa-", "bit-", "osv-"];

    /// <summary>
    /// True when the token adds nothing: it is one of the query's own ids, part of its subject, or
    /// an alias of them.
    /// </summary>
    /// <remarks>
    /// The <c>@</c> split is for package coordinates. OSV writes <c>'SixLabors.ImageSharp@1.0.4'</c>
    /// as one token while the subject arrived as two words, and without the split the coordinate
    /// reads as new information and survives into a query that already names it.
    /// </remarks>
    private static bool AlreadyNamed(string bare, HashSet<string> named)
    {
        if (named.Contains(bare) || IsAdvisoryId(bare)) return true;

        var parts = bare.Split('@', StringSplitOptions.RemoveEmptyEntries);

        return parts.Length > 1 && parts.All(p => named.Contains(p) || IsAdvisoryId(p));
    }

    private static bool IsAdvisoryId(string bare) =>
        AdvisoryPrefixes.Any(p => bare.StartsWith(p, StringComparison.Ordinal));

    private static bool IsLink(string token) =>
        token.Contains("://", StringComparison.Ordinal)
        || token.Contains("](", StringComparison.Ordinal)
        || token.StartsWith("www.", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The marker <c>RegexSecretScanner</c> leaves behind. It is proof the gate ran, not something
    /// to search a corpus for, and every redacted finding would otherwise share the same token.
    /// </summary>
    private static bool IsRedactionMarker(string bare) =>
        bare.StartsWith("[redacted", StringComparison.Ordinal)
        || bare.StartsWith("redacted:", StringComparison.Ordinal);
}
