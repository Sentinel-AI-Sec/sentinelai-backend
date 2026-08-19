using System.Text.RegularExpressions;

namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>
/// Strips scanner boilerplate out of a finding's message, leaving the prose an embedding model
/// can actually match against corpus text.
/// </summary>
/// <remarks>
/// <para>
/// The corpus was cleaned of CVSS vectors, URLs and markup at ingest (SEC-07), so a query
/// carrying <c>CVSS:3.1/AV:N/AC:L</c> or <c>src/OrderApp/OrdersController.cs:47</c> spends the
/// model's attention on tokens that appear nowhere in the index. Those tokens are not merely
/// useless — they crowd out the words that would have matched.
/// </para>
/// <para>
/// <b>Two traps, both already hit in this project, both pinned by tests.</b>
/// </para>
/// <list type="number">
/// <item>
/// <description>
/// A naive path-stripper eats <c>Newtonsoft.Json</c>. It looks exactly like a filename — a word,
/// a dot, an extension — and it is the single most important token in the fixture's dependency
/// query. The rule below therefore treats a dotted token as a path only when it carries a
/// directory separator, or ends in an extension that no NuGet package ever ends in. Notably
/// <c>.json</c>, <c>.xml</c>, <c>.config</c> and <c>.lock</c> are excluded from the bare-name
/// case for exactly this reason.
/// </description>
/// </item>
/// <item>
/// <description>
/// A naive markdown cleaner eats <c>s3:*</c>. Treating <c>*</c> as emphasis deletes the wildcard
/// that is the entire content of an over-permissioned IAM finding, turning "grants s3:* on the
/// bucket" into "grants s3: on the bucket". Nothing here touches <c>*</c>; only the backtick
/// characters are removed, and their contents are kept.
/// </description>
/// </item>
/// </list>
/// <para>
/// CVE and CWE identifiers are deliberately <em>left in</em>. They are what the acceptance
/// criterion asks the query to carry, and <see cref="FindingQueryBuilder"/> checks the cleaned
/// text before appending its own identifier clause so nothing is stated twice.
/// </para>
/// </remarks>
public static partial class QueryTextSanitizer
{
    /// <summary>
    /// Label prefixes that begin a pure metadata line in a multi-line scanner message. Trivy's
    /// message body is four of these stacked up; none of them is prose.
    /// </summary>
    /// <remarks>
    /// <c>Package</c> and <c>Installed Version</c> are dropped here even though the query needs
    /// them, because <see cref="PackageCoordinate"/> has already read them off the finding by the
    /// time this runs. Reading a value and then deleting the label that carried it is the point:
    /// the coordinate lands in the template slot it belongs in instead of trailing a colon.
    /// </remarks>
    private static readonly string[] BoilerplateLabels =
    [
        "package", "installed version", "fixed version", "severity", "status", "type",
        "vulnerability id", "rule", "check", "check_id", "check id", "guideline", "resource",
        "file", "line", "cvss", "score", "published", "last modified", "references", "target",
        "class", "vulnerable package", "affected version", "patched version",
    ];

    /// <summary>Any path that carries a directory separator, with an optional <c>:line[:col]</c>.</summary>
    /// <remarks>
    /// Path segments hold no spaces on purpose. Allowing them lets the pattern run across a
    /// sentence — "grants s3:GetObject/PutObject on customer.data" reads as one long path and
    /// the whole clause disappears. Spaces in a repo path are rare; eating an IAM action list is
    /// not a trade worth making.
    /// </remarks>
    [GeneratedRegex(
        @"(?<![\w])(?:file:/{0,3})?(?:[A-Za-z]:[\\/])?[\w.\-]+(?:[\\/][\w.\-]+)+\.[A-Za-z][\w]{0,9}(?::\d+(?::\d+)?)?",
        RegexOptions.CultureInvariant)]
    private static partial Regex PathWithSeparator();

    /// <summary>
    /// A bare filename, restricted to extensions that cannot be the tail of a package name.
    /// </summary>
    /// <remarks>
    /// This list is the <c>Newtonsoft.Json</c> guard. Adding <c>json</c>, <c>xml</c>,
    /// <c>config</c> or <c>lock</c> to it would delete package names from dependency queries —
    /// which is why the regression test names them.
    /// </remarks>
    [GeneratedRegex(
        @"(?<![\w./\\-])[\w\-]+(?:\.[\w\-]+)*\.(?:cs|vb|fs|tf|tfvars|tfstate|hcl|ya?ml|csproj|vbproj|fsproj|sln|slnx|props|targets|py|js|jsx|ts|tsx|java|go|rb|php|sh|ps1|bat|cmd)(?::\d+(?::\d+)?)?(?![\w])",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BareSourceFileName();

    /// <summary>
    /// Manifest file names whose extensions are excluded above, listed explicitly so the common
    /// ones still go rather than being kept for the sake of one package-name guard.
    /// </summary>
    [GeneratedRegex(
        @"(?<![\w./\\-])(?:packages\.lock\.json|packages\.config|package-lock\.json|[\w.\-]+\.deps\.json|[\w.\-]+\.nuspec|yarn\.lock|go\.sum|Gemfile\.lock|requirements\.txt)(?![\w])",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ManifestFileName();

    /// <summary>A CVSS vector string. Anchored on <c>CVSS:</c>, so <c>s3:*</c> cannot match.</summary>
    [GeneratedRegex(@"CVSS:\d(?:\.\d)?/[A-Za-z]{1,2}:[A-Za-z](?:/[A-Za-z]{1,2}:[A-Za-z])*",
        RegexOptions.CultureInvariant)]
    private static partial Regex CvssVector();

    /// <summary>
    /// A "see &lt;link&gt;" pointer, taken out as a unit rather than leaving the verb behind.
    /// </summary>
    /// <remarks>
    /// Removing only the URL turns "… is vulnerable. See https://nvd.nist.gov/…" into
    /// "… is vulnerable. See" — a dangling word that survives every later cleanup because it is
    /// a perfectly ordinary token. It costs nothing to read and nothing to embed, so it goes with
    /// the link it introduced.
    /// </remarks>
    [GeneratedRegex(
        // Leading whitespace and commas go with it; a full stop does not — it belongs to the
        // sentence that ended before the pointer began.
        @"[\s,;]*\b(?:see(?:\s+also)?|refer\s+to|more\s+(?:info(?:rmation)?|details?)\s+at|references?)\b\s*:?\s*(?:https?|ftp|file)://\S+",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LinkPointer();

    [GeneratedRegex(@"\b(?:https?|ftp|file)://\S+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Url();

    /// <summary>"also known as 'GHSA-…'", "(aka CVE-…)" — alias noise the corpus never carries.</summary>
    [GeneratedRegex(@"\s*\((?:also known as|aka|see also)[^)]*\)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex AliasClause();

    /// <summary>
    /// Tool rule ids. Never CVE/CWE — those are the identifiers the query must keep.
    /// </summary>
    /// <remarks>
    /// Only the five scanners this project runs are listed. A looser pattern such as
    /// <c>[A-Z]\d{3,4}</c> would catch other tools' ids and also delete real tokens like a
    /// version or a port number out of a description.
    /// </remarks>
    [GeneratedRegex(
        @"(?<![\w\-])(?:SCS\d{4}|CKV\d?_[A-Z]+_\d+|AVD-[A-Z]+-\d+|GHSA(?:-[a-z0-9]{4}){3}|DS\d{3})(?![\w\-])",
        RegexOptions.CultureInvariant)]
    private static partial Regex ToolRuleId();

    [GeneratedRegex(@"\b(?:at|on|in)\s+line\s+\d+(?:\s*,?\s*column\s+\d+)?\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex LineReference();

    /// <summary>Empty quotes/brackets and doubled punctuation left where something was removed.</summary>
    [GeneratedRegex(@"(?:''|""""|\(\s*\)|\[\s*\]|\{\s*\})", RegexOptions.CultureInvariant)]
    private static partial Regex EmptyDelimiters();

    [GeneratedRegex(@"\s+", RegexOptions.CultureInvariant)]
    private static partial Regex Whitespace();

    [GeneratedRegex(@"\s+([,.;:!?])", RegexOptions.CultureInvariant)]
    private static partial Regex SpaceBeforePunctuation();

    /// <summary>
    /// Punctuation left stranded by a removal — "text, , more" — collapsed back to one mark.
    /// </summary>
    /// <remarks>
    /// The run must be <em>separated by whitespace</em> to count. A pattern that collapsed
    /// adjacent punctuation instead would rewrite <c>arn:aws:s3:::customer-data-bucket/*</c> as
    /// <c>arn:aws:s3:customer-data-bucket/*</c> — a third trap of the same family as the two in
    /// the class summary, and the one this codebase actually tripped over first.
    /// </remarks>
    [GeneratedRegex(@"([,;:])(?:\s+[,;:])+", RegexOptions.CultureInvariant)]
    private static partial Regex RepeatedPunctuation();

    /// <summary>
    /// The finding's message with everything the corpus never contained taken out of it.
    /// Returns an empty string when nothing survives — the caller decides what to do about that.
    /// </summary>
    public static string Clean(string? message)
    {
        if (string.IsNullOrWhiteSpace(message)) return string.Empty;

        var prose = string.Join(' ', ProseLines(message));

        // Order matters. Aliases come out whole before rule ids, or "(also known as 'GHSA-…')"
        // loses its id and leaves "(also known as '')" behind. Paths with separators come out
        // before bare names, so a path is never half-eaten from its tail.
        prose = AliasClause().Replace(prose, " ");
        prose = CvssVector().Replace(prose, " ");
        prose = LinkPointer().Replace(prose, " ");
        prose = Url().Replace(prose, " ");
        prose = PathWithSeparator().Replace(prose, " ");
        prose = ManifestFileName().Replace(prose, " ");
        prose = BareSourceFileName().Replace(prose, " ");
        prose = ToolRuleId().Replace(prose, " ");
        prose = LineReference().Replace(prose, " ");

        // Backticks only. The characters go, whatever they wrapped stays — `s3:*` must survive.
        prose = prose.Replace("`", string.Empty);

        prose = EmptyDelimiters().Replace(prose, " ");
        prose = Whitespace().Replace(prose, " ").Trim();
        prose = RepeatedPunctuation().Replace(prose, "$1");
        prose = SpaceBeforePunctuation().Replace(prose, "$1");

        return prose.Trim(' ', ',', ';', ':', '-', '–', '—');
    }

    /// <summary>
    /// The lines of a scanner message that are prose rather than a <c>Label: value</c> pair.
    /// </summary>
    /// <remarks>
    /// Split by line rather than by regex over the whole body because the labels only mean
    /// "metadata" at the start of a line. "Severity:" opening a line is Trivy's header; the same
    /// word mid-sentence is part of a description.
    /// </remarks>
    private static IEnumerable<string> ProseLines(string message)
    {
        foreach (var raw in message.Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();
            if (line.Length == 0 || IsBoilerplateLine(line)) continue;
            yield return line;
        }
    }

    private static bool IsBoilerplateLine(string line)
    {
        var colon = line.IndexOf(':');
        if (colon <= 0) return false;

        var label = line[..colon].Trim().ToLowerInvariant();
        return BoilerplateLabels.Contains(label);
    }
}
