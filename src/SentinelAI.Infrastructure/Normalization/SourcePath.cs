namespace SentinelAI.Infrastructure.Normalization;

/// <summary>
/// Turns a SARIF <c>artifactLocation.uri</c> into a stable, repo-relative path.
/// </summary>
/// <remarks>
/// <para>
/// Scanners disagree about what a location is. Checkov writes <c>infra/iam.tf</c> and Trivy
/// writes <c>src/OrderApp/OrderApp.deps.json</c> — both already repo-relative — while Roslyn
/// and OSV-Scanner emit the build agent's absolute path, baked in with whatever directory the
/// checkout happened to land in:
/// </para>
/// <code>
/// file:///C:/Users/PC_STORE/Downloads/sentinelai-fixture_2/sentinelai-fixture/src/OrderApp/Controllers/OrdersController.cs
/// </code>
/// <para>
/// That string is why this class exists. The path feeds the dedup key and the node reference,
/// so left as-is the same finding scanned on two machines dedups as two findings and lands on
/// two different graph nodes — the silent island failure SEC-03 exists to prevent, arriving
/// through the back door.
/// </para>
/// <para>
/// The proper fix is upstream: the runner should emit repo-relative URIs. Until it does, this
/// recovers the repo-relative tail by cutting at the outermost well-known project root
/// directory. It is a heuristic and is written to fail small — an unrecognized absolute path
/// degrades to its file name, which is still machine-independent, rather than to a path
/// carrying somebody's home directory.
/// </para>
/// </remarks>
internal static class SourcePath
{
    /// <summary>
    /// Directory names that begin a repo-relative path. The cut is made at the <em>first</em>
    /// of these, so <c>.../fixture/src/OrderApp/Controllers/X.cs</c> keeps
    /// <c>src/OrderApp/Controllers/X.cs</c> and does not cut again at a nested <c>src</c>.
    /// </summary>
    private static readonly string[] ProjectRoots =
        ["src", "source", "app", "apps", "lib", "test", "tests", "infra", "infrastructure", "deploy", "terraform"];

    /// <summary>
    /// The repo-relative form of a scanner-reported URI, or null when there is nothing usable.
    /// </summary>
    public static string? Normalize(string? uri)
    {
        if (string.IsNullOrWhiteSpace(uri)) return null;

        var path = StripScheme(uri.Trim()).Replace('\\', '/');

        // A drive letter or a leading slash is what makes a path absolute; either way the
        // segments before the project root belong to the machine, not the repository.
        var isAbsolute = path.StartsWith('/') || (path.Length > 1 && path[1] == ':');

        var segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0) return null;

        if (!isAbsolute)
            return string.Join('/', segments);

        for (var i = 0; i < segments.Length - 1; i++)
        {
            if (ProjectRoots.Contains(segments[i], StringComparer.OrdinalIgnoreCase))
                return string.Join('/', segments[i..]);
        }

        // No recognizable root: keep the file name. Less useful than a path, but it is the same
        // on every machine, which is the property that actually matters here.
        return segments[^1];
    }

    /// <summary>
    /// The location as it is stored on a finding: the repo-relative path, plus the line when
    /// the tool reported one, so two different problems in one file stay two findings.
    /// </summary>
    public static string? WithLine(string? uri, int? line)
    {
        var path = Normalize(uri);
        if (path is null) return null;

        return line is > 0 ? $"{path}:{line}" : path;
    }

    /// <summary>Removes a <c>file://</c> prefix and percent-decodes what is left.</summary>
    private static string StripScheme(string uri)
    {
        const string fileScheme = "file://";
        if (uri.StartsWith(fileScheme, StringComparison.OrdinalIgnoreCase))
            uri = uri[fileScheme.Length..];

        // "file:///C:/..." leaves a leading slash before the drive letter.
        if (uri.Length > 2 && uri[0] == '/' && uri[2] == ':')
            uri = uri[1..];

        return Uri.UnescapeDataString(uri);
    }
}
