using System.Text.Json;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-18 part A, step 1: reads NuGet's <c>packages.lock.json</c> format into a flat package
/// list — every package under every target framework's <c>dependencies</c> object, direct and
/// transitive alike, since the ticket treats them the same way (both become <c>Pkg</c> nodes
/// with a <c>used-by</c> edge). No canonicalization here — that is
/// <see cref="DepCodeSeamReader"/>'s job, same split as <see cref="TerraformDotParser"/> (raw
/// parse) vs <see cref="TerraformInfraSpineReader"/> (canonicalize).
/// </summary>
/// <remarks>
/// Hand-rolled over <c>System.Text.Json</c> rather than a NuGet SDK package: the lock file shape
/// this reads is small, stable, and documented by NuGet itself (a <c>version</c> field, a
/// <c>dependencies</c> object keyed by target framework, each package's <c>type</c> of
/// <c>"Direct"</c> or <c>"Transitive"</c>, and its <c>resolved</c> version) — pulling in a
/// package-management SDK to read four fields would be a heavier dependency than the problem
/// warrants.
/// </remarks>
internal static class NuGetLockFileParser
{
    public static IReadOnlyList<NuGetLockPackage> Parse(string lockFileJson)
    {
        if (string.IsNullOrWhiteSpace(lockFileJson)) return [];

        using var document = JsonDocument.Parse(lockFileJson);
        if (!document.RootElement.TryGetProperty("dependencies", out var dependenciesByFramework))
            return [];

        // One package can appear under more than one target framework (net8.0 and net9.0
        // resolving to the same version, say) — keyed by name so it becomes one Pkg node, not
        // one per framework. The first occurrence wins on a version disagreement across
        // frameworks; multi-targeting version skew is a real but rare case this ticket's fixture
        // does not exercise, and silently keeping the first is safer than guessing which
        // framework "wins".
        var packagesByName = new Dictionary<string, NuGetLockPackage>(StringComparer.OrdinalIgnoreCase);

        foreach (var frameworkEntry in dependenciesByFramework.EnumerateObject())
        {
            foreach (var packageEntry in frameworkEntry.Value.EnumerateObject())
            {
                var name = packageEntry.Name;
                if (string.IsNullOrWhiteSpace(name) || packagesByName.ContainsKey(name)) continue;

                var resolved = packageEntry.Value.TryGetProperty("resolved", out var resolvedProp)
                    ? resolvedProp.GetString() ?? string.Empty
                    : string.Empty;

                var isDirect = packageEntry.Value.TryGetProperty("type", out var typeProp)
                    && string.Equals(typeProp.GetString(), "Direct", StringComparison.OrdinalIgnoreCase);

                packagesByName[name] = new NuGetLockPackage(name, resolved, isDirect);
            }
        }

        return [.. packagesByName.Values];
    }
}

/// <param name="Name">The NuGet package id, e.g. <c>Newtonsoft.Json</c>.</param>
/// <param name="Version">The resolved version, e.g. <c>13.0.3</c>. Empty if the lock file
/// entry carried no <c>resolved</c> field.</param>
/// <param name="IsDirect">True for a package this project references directly (<c>"type":
/// "Direct"</c>); false for a transitive dependency pulled in by another package.</param>
internal sealed record NuGetLockPackage(string Name, string Version, bool IsDirect);
