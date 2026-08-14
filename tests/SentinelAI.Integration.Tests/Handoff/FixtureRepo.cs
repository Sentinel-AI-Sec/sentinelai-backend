using System.Reflection;

namespace SentinelAI.Integration.Tests.Handoff;

/// <summary>
/// Locates the committed <c>sentinelai-fixtures</c> repository on disk, so a test can assert
/// against the bytes the scanners actually ran over instead of a constant somebody pasted.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists at all.</b> Every fixture input in this solution is a <c>const</c> string.
/// A constant cannot drift from the product, but it drifts from the fixture, and that is the
/// same failure wearing a different hat: for one sprint <c>FlagshipChainTests</c> asserted the
/// flagship chain over a Dockerfile carrying <c>LABEL org.sentinelai.image</c> that the real
/// fixture did not have. The test was green and the product was broken. Reading the file is the
/// only thing that closes that gap.
/// </para>
/// <para>
/// <b>Why it may legitimately not be found.</b> The fixtures live in a sibling repository, not a
/// submodule, so a CI job that checks out only the backend has no fixtures to read. A test that
/// depends on this therefore <em>skips</em> with a stated reason rather than failing — see
/// <see cref="CommittedFixtureFactAttribute"/>. A skip is honest ("not measured here"); a
/// failure would be a lie about the code, and a silent pass would be worse than either.
/// </para>
/// </remarks>
internal static class FixtureRepo
{
    /// <summary>The sibling repository's directory name.</summary>
    private const string DirectoryName = "sentinelai-fixtures";

    /// <summary>
    /// A file that must be inside it. Without this, any empty directory that happens to carry
    /// the right name would satisfy the search and every from-disk assertion below would then
    /// fail for a reason that has nothing to do with the product.
    /// </summary>
    private static readonly string Marker = Path.Combine("scan_out", "roslyn.sarif");

    /// <summary>
    /// The fixture repository root, or null when it is not checked out beside this one.
    /// </summary>
    /// <remarks>
    /// Walks up from the test assembly rather than hard-coding an absolute path: the same test
    /// has to run from <c>tests/…/bin/Debug/net10.0</c> on a developer's machine and from
    /// whatever directory CI unpacks into, and an absolute path would pin it to one laptop.
    /// </remarks>
    public static string? Root { get; } = Find();

    public static string Require() =>
        Root ?? throw new InvalidOperationException($"{DirectoryName} was not found; this test should have skipped");

    /// <summary>The reason string a skipped test reports. Names the search so the skip is actionable.</summary>
    public static string SkipReason =>
        $"'{DirectoryName}' was not found beside this repository (searched upward from "
        + $"'{StartDirectory()}' for a directory containing '{Marker}'). The fixtures are a "
        + "sibling repository, not a submodule, so this is expected on a backend-only checkout.";

    private static string StartDirectory() =>
        Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) is { Length: > 0 } assemblyDirectory
            ? assemblyDirectory
            : AppContext.BaseDirectory;

    private static string? Find()
    {
        for (var directory = new DirectoryInfo(StartDirectory()); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, DirectoryName);
            if (File.Exists(Path.Combine(candidate, Marker))) return candidate;
        }

        return null;
    }
}

/// <summary>
/// A <see cref="FactAttribute"/> that skips itself, with a reason, when the fixture repository
/// is absent.
/// </summary>
/// <remarks>
/// xunit 2.9 has no dynamic <c>Assert.Skip</c>, so the decision has to be made when the attribute
/// is constructed. That is fine here: whether a sibling directory exists does not change during a
/// test run.
/// </remarks>
internal sealed class CommittedFixtureFactAttribute : FactAttribute
{
    public CommittedFixtureFactAttribute()
    {
        if (FixtureRepo.Root is null) Skip = FixtureRepo.SkipReason;
    }
}
