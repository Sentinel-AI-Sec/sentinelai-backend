using System.Text.RegularExpressions;

namespace SentinelAI.Application.Features.Scan.Security;

/// <summary>
/// What one entry in a received bundle is, as far as the backend is concerned.
/// </summary>
public enum BundleEntryKind
{
    /// <summary>A file the bundle contract says may be here.</summary>
    Expected,

    /// <summary>
    /// Application source. The bundle must never contain any — this is the product's
    /// "your code never leaves your runner" promise, failing.
    /// </summary>
    ApplicationSource,

    /// <summary>
    /// Not source by extension, but not part of the bundle contract either. Refused for
    /// the reason given in <see cref="BundleContentPolicy"/>: we cannot claim "bundle only"
    /// while accepting files whose contents nobody has characterised.
    /// </summary>
    OutsideLayout,
}

/// <param name="IsAccepted">False if anything at all was refused.</param>
/// <param name="SourceFiles">Entries that are application source. Non-empty means the runner-side guard failed.</param>
/// <param name="OutsideLayout">Entries that are not source but are not part of the bundle contract.</param>
/// <param name="Error">Operator-readable reason, or null when accepted.</param>
public sealed record BundleContentDecision(
    bool IsAccepted,
    IReadOnlyList<string> SourceFiles,
    IReadOnlyList<string> OutsideLayout,
    string? Error)
{
    public static readonly BundleContentDecision Accepted = new(true, [], [], null);
}

/// <summary>
/// SEC-34 box 2, enforced on our side: a received bundle contains the artifacts the runner
/// was supposed to collect, and nothing else — no application source to process.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists when three other guards already claim it.</b> The runner's collector
/// (<c>collect-graph-inputs.sh</c>) is a whitelist and says so in its own header; the runner
/// then runs <c>assert-no-source.sh</c> twice, and <see cref="Domain.Abstractions.Repositories.IBundleInspector"/>
/// applies an extension denylist on ingest. Four claims, all true, and the property was still
/// unasserted by anything we run and can fail. Two of those checks live on the customer's
/// machine, where they can be skipped; the tarball pass of the third has been reported as
/// vacuous by five consecutive audits (it passes when nothing was built). This one runs on
/// infrastructure we control, on the entry list of the bundle that actually arrived, on the
/// path that actually accepts jobs. A property that holds by construction somewhere else is
/// not the same as a property we verified.
/// </para>
/// <para>
/// <b>Why an allowlist rather than a denylist of source extensions.</b> The ingest inspector
/// already carries such a denylist, and its gap is the argument: it blocks <c>.ts</c>,
/// <c>.tsx</c> and <c>.jsx</c> but not <c>.js</c>, so an entire Node application could be
/// uploaded and every guard in the chain would report a pass. Any denylist has that shape —
/// it is a list of the languages someone thought of. The bundle contract, by contrast, is
/// short and known: <c>metadata.json</c>, <c>scanner-versions.json</c>, <c>findings/*</c>,
/// and the seven graph-input patterns the collector copies. Everything else is refused,
/// including files nobody has a name for yet.
/// </para>
/// <para>
/// <b>Why the source list is kept as well.</b> The two rejections mean different things. A
/// <c>.cs</c> file in the bundle is a defect in the Action worth paging someone about; a
/// stray <c>README.md</c> is a contract drift worth a bug. The decision reports them
/// separately so the message can say which happened, and so the source case can be logged at
/// error level while the other is not.
/// </para>
/// <para>
/// <b>What this does not check.</b> Only names. A <c>.tf</c> file whose body is C# passes,
/// and so does a <c>findings/*.sarif</c> whose <c>snippet</c> fields quote the customer's
/// source — SARIF legitimately carries code excerpts, and refusing those would refuse every
/// real Roslyn report. Content-level protection for what reaches a model is the ingress
/// redaction gate's job (SEC-33), not this one's.
/// </para>
/// </remarks>
public static partial class BundleContentPolicy
{
    /// <summary>Everything the runner collected for the graph lives under this prefix.</summary>
    public const string GraphInputsPrefix = "graph-inputs/";

    /// <summary>The scanners' raw output lives under this prefix.</summary>
    public const string FindingsPrefix = "findings/";

    /// <summary>The only two files allowed at the bundle root.</summary>
    private static readonly string[] RootFiles = ["metadata.json", "scanner-versions.json"];

    /// <summary>
    /// Application source in any language we might plausibly meet.
    /// </summary>
    /// <remarks>
    /// This deliberately includes the extensions the ingest inspector's copy omits —
    /// <c>.js</c>, <c>.mjs</c>, <c>.cjs</c>, <c>.sql</c>, <c>.sh</c>, <c>.ps1</c> and the
    /// rest. It exists to classify, not to be the gate: the gate is the layout allowlist
    /// below, which refuses these whether or not they are on this list. What the list buys is
    /// a truthful error message — "application source", not "unexpected file" — for the case
    /// that means the Action is broken.
    /// </remarks>
    [GeneratedRegex(
        @"\.(cs|vb|fs|fsx|fsi|cshtml|razor|aspx|asax|ascx|java|kt|kts|scala|groovy|clj|py|pyw|pyi"
        + @"|rb|php|go|rs|ts|tsx|js|jsx|mjs|cjs|vue|svelte|c|cc|cpp|cxx|h|hh|hpp|hxx|m|mm|swift"
        + @"|dart|ex|exs|erl|lua|pl|pm|r|sql|sh|bash|zsh|ps1|psm1|bat|cmd)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex ApplicationSourceExtension();

    /// <summary>
    /// The graph inputs the collector copies, mirrored pattern for pattern from
    /// <c>collect-graph-inputs.sh</c>: <c>*.tf</c>, <c>*.tf.json</c>, <c>Dockerfile</c>,
    /// <c>Dockerfile.*</c>, <c>*.csproj</c>, <c>packages.lock.json</c>,
    /// <c>package-lock.json</c>, plus the <c>terraform graph</c> DOT the script writes itself.
    /// </summary>
    /// <remarks>
    /// Matched on the file name only, because the collector preserves relative paths so two
    /// Dockerfiles in different services do not collide — <c>graph-inputs/src/OrderApp/Dockerfile</c>
    /// is the normal shape, not an anomaly. If the collector grows a pattern, this list has to
    /// grow with it or real bundles start being refused; that coupling is the price of the
    /// property being checked rather than assumed, and it fails closed.
    /// </remarks>
    [GeneratedRegex(
        @"^(terraform-graph\.dot|.+\.tf|.+\.tf\.json|Dockerfile|Dockerfile\..+|.+\.csproj"
        + @"|packages\.lock\.json|package-lock\.json)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex GraphInputName();

    /// <summary>The scanners emit SARIF; OSV can emit its own JSON. Nothing else belongs here.</summary>
    [GeneratedRegex(@"\.(sarif|json)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex FindingsFileName();

    /// <summary>
    /// Classifies every entry and returns the verdict for the bundle as a whole.
    /// </summary>
    /// <param name="entries">
    /// Bundle-root-relative paths, as the inspector enumerated them. Directory entries are
    /// not expected and are ignored if present — an empty segment carries no content.
    /// </param>
    public static BundleContentDecision Evaluate(IReadOnlyList<string> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        List<string>? source = null;
        List<string>? outside = null;

        foreach (var entry in entries)
        {
            var name = Normalize(entry);
            if (name.Length == 0 || name.EndsWith('/')) continue;

            switch (Classify(name))
            {
                case BundleEntryKind.ApplicationSource:
                    (source ??= []).Add(name);
                    break;
                case BundleEntryKind.OutsideLayout:
                    (outside ??= []).Add(name);
                    break;
            }
        }

        if (source is null && outside is null)
            return BundleContentDecision.Accepted;

        return new BundleContentDecision(
            IsAccepted: false,
            SourceFiles: source ?? [],
            OutsideLayout: outside ?? [],
            Error: Describe(source, outside));
    }

    /// <summary>
    /// What a single entry is.
    /// </summary>
    /// <remarks>
    /// Source is tested first, so a <c>.py</c> sitting under <c>graph-inputs/</c> is reported
    /// as source rather than as a layout violation. The distinction is not cosmetic: the
    /// first says the Action's whitelist was bypassed, the second says the contract drifted.
    /// </remarks>
    public static BundleEntryKind Classify(string entry)
    {
        var name = Normalize(entry);

        if (ApplicationSourceExtension().IsMatch(name))
            return BundleEntryKind.ApplicationSource;

        if (RootFiles.Contains(name, StringComparer.OrdinalIgnoreCase))
            return BundleEntryKind.Expected;

        if (name.StartsWith(FindingsPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return FindingsFileName().IsMatch(name)
                ? BundleEntryKind.Expected
                : BundleEntryKind.OutsideLayout;
        }

        if (name.StartsWith(GraphInputsPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var fileName = name[(name.LastIndexOf('/') + 1)..];
            return GraphInputName().IsMatch(fileName)
                ? BundleEntryKind.Expected
                : BundleEntryKind.OutsideLayout;
        }

        return BundleEntryKind.OutsideLayout;
    }

    /// <summary>
    /// The rejection message. Names the offenders — up to five — because "the bundle was
    /// refused" with no file name is a message whose only possible next step is to ask us.
    /// </summary>
    private static string Describe(List<string>? source, List<string>? outside)
    {
        if (source is { Count: > 0 })
        {
            return $"the bundle contains application source ({source.Count} file(s): "
                + $"{string.Join(", ", source.Take(5))}) and was refused. The runner-side "
                + "collector is a whitelist, so this means the Action's guard did not run.";
        }

        return $"the bundle contains {outside!.Count} file(s) outside the bundle contract: "
            + $"{string.Join(", ", outside.Take(5))}. A bundle may contain metadata.json, "
            + "scanner-versions.json, findings/*.sarif|json, and the collector's graph-inputs "
            + "patterns — nothing else.";
    }

    /// <summary>Tar writes leading <c>./</c>; comparisons here do not want it.</summary>
    private static string Normalize(string name) =>
        name.Replace('\\', '/').TrimStart('.', '/');
}
