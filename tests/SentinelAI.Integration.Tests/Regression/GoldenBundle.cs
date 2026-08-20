using System.Reflection;
using SentinelAI.Integration.Tests.Handoff;
using SentinelAI.Integration.Tests.Scan;

namespace SentinelAI.Integration.Tests.Regression;

/// <summary>
/// The bundle the SEC-49 regression harness runs over: the reference fixture's three-layer
/// golden path, read from <c>samples/golden-bundle/</c> and packed into a real <c>.tar.gz</c>
/// the ingest endpoint accepts.
/// </summary>
/// <remarks>
/// <para>
/// <b>Real files on disk, not constants in this class.</b> The first version held every
/// Terraform block and SARIF document as a C# string literal, and that is the shape with the
/// worst history in this repository: for one sprint <c>FlagshipChainTests</c> asserted the
/// flagship chain over a Dockerfile carrying <c>LABEL org.sentinelai.image</c> that the real
/// fixture did not have — green the whole time, broken the whole time. <c>FixtureRepo</c>'s own
/// docstring draws the conclusion: <em>prefer adding a from-disk assertion over adding a
/// constant</em>. Reading the files is that, and it buys a second thing besides — the demo
/// driver (<c>scripts/demo.sh</c>) packs the same directory, so the acceptance demo runs over
/// exactly the bytes CI proves.
/// </para>
/// <para>
/// <b>Why the bytes are committed here at all.</b> The fixtures are a sibling repository, not a
/// submodule, so a backend-only checkout — which is what CI does — has none of them. A harness
/// that skipped there would be a regression harness that never runs on the change that broke
/// something. <see cref="FixtureParityTests"/> compares this directory against
/// <c>sentinelai-fixtures</c> whenever that repository is checked out beside this one, and skips
/// with a stated reason when it is not: measured everywhere, verified wherever verification is
/// possible.
/// </para>
/// <para>
/// <b>What "golden path" means here.</b> One chain, four hops, crossing every layer the product
/// claims to reason across:
/// </para>
/// <code>
/// pkg:newtonsoft.json  --used-by-->  code:orderapp  --deployed-as-->
///     task:order_task  --assumes-->  iam_role:order_task_role  --can-access-->  s3:customer_data
/// </code>
/// <para>
/// Plus one deliberate distractor — <c>legacy_worker_task</c>, whose image comes from a variable
/// that resolves to no Dockerfile here — so the harness covers the unresolved-join tier as well
/// as the happy one.
/// </para>
/// </remarks>
internal static class GoldenBundle
{
    /// <summary>The directory the bundle's files live in, relative to the repository root.</summary>
    private const string DirectoryName = "samples/golden-bundle";

    /// <summary>
    /// A file that must be inside it, so an empty directory of the right name cannot satisfy
    /// the search and leave every assertion failing for an unrelated reason.
    /// </summary>
    private static readonly string Marker = Path.Combine("graph-inputs", "infra", "iam.tf");

    /// <summary>
    /// The bundle directory, located by walking up from the test assembly.
    /// </summary>
    /// <remarks>
    /// The same technique <see cref="FixtureRepo"/> uses, and for the same reason: this test has
    /// to run from <c>tests/…/bin/Debug/net10.0</c> on a developer's machine and from whatever
    /// directory CI unpacks into, and an absolute path would pin it to one laptop.
    /// </remarks>
    public static string Root { get; } = Find()
        ?? throw new InvalidOperationException(
            $"'{DirectoryName}' was not found above '{StartDirectory()}'. It is committed in this "
            + "repository, so this means the test assembly is running from somewhere unexpected "
            + "rather than that anything is missing.");

    private static string StartDirectory() =>
        Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location) is { Length: > 0 } assemblyDirectory
            ? assemblyDirectory
            : AppContext.BaseDirectory;

    private static string? Find()
    {
        var relative = DirectoryName.Replace('/', Path.DirectorySeparatorChar);

        for (var directory = new DirectoryInfo(StartDirectory()); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, relative);
            if (File.Exists(Path.Combine(candidate, Marker))) return candidate;
        }

        return null;
    }

    /// <summary>One file's text, by its path inside the bundle.</summary>
    public static string Read(string pathInBundle) =>
        File.ReadAllText(Path.Combine(Root, pathInBundle.Replace('/', Path.DirectorySeparatorChar)));

    /// <summary>
    /// The bundle's own metadata copy.
    /// </summary>
    /// <remarks>
    /// Generated rather than committed, because it carries the project id and commit sha of
    /// whatever run is happening. The endpoint parses the <em>multipart</em> metadata part rather
    /// than this file; it is in the tarball because the bundle layout allowlist expects it.
    /// </remarks>
    public static string MetadataJson(Guid projectId, string commitSha) =>
        $$"""
        {"project_id":"{{projectId}}","commit_sha":"{{commitSha}}","pr_ref":"pr/49","retain_report":true,"runner_secret_scan":"passed"}
        """;

    /// <summary>
    /// Every entry of the golden bundle, keyed by its path inside the tarball.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Enumerated from disk rather than listed here, so a file added to
    /// <c>samples/golden-bundle/</c> is in the bundle without anyone remembering to name it —
    /// and, more importantly, so a file <em>removed</em> from it cannot leave a stale entry
    /// behind in a list nothing reads.
    /// </para>
    /// <para>
    /// The <c>graph-inputs/</c> prefix and the repo-relative paths under it are part of the
    /// contract, not decoration: the graph stage strips the prefix and reads a project name out
    /// of what is left, and Checkov's <c>infra/iam.tf</c> location only joins a Terraform block
    /// because the file is at <c>graph-inputs/infra/iam.tf</c>.
    /// </para>
    /// </remarks>
    public static Dictionary<string, string> Files(Guid projectId, string commitSha)
    {
        var files = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["metadata.json"] = MetadataJson(projectId, commitSha),
        };

        foreach (var path in Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories))
        {
            var name = Path.GetRelativePath(Root, path).Replace('\\', '/');

            // README.md is documentation for a human opening the directory, and the bundle
            // layout allowlist would refuse it — correctly, since it is not something the
            // collector produces.
            if (name.Equals("README.md", StringComparison.OrdinalIgnoreCase)) continue;

            files[name] = File.ReadAllText(path);
        }

        return files;
    }

    /// <summary>The bundle as the bytes the Action would upload.</summary>
    public static byte[] TarGz(Guid projectId, string commitSha = "49c0ffee") =>
        TarGzTestHelper.Build(Files(projectId, commitSha)).ToArray();

    // ---- the expected result, as constants the harness asserts against --------------------

    /// <summary>
    /// The flagship chain's node keys, in attack order.
    /// </summary>
    /// <remarks>
    /// The IAM role's key is <c>iam_role:</c> while its node <em>type</em> is <c>role</c> — the
    /// prefix is historical and the read API preserves it deliberately (see
    /// <c>ReadApiContractTests.An_iam_role_node_is_typed_role_while_its_key_keeps_the_historical_prefix</c>).
    /// Written out as it really is rather than as it reads best, because a harness asserting the
    /// tidier spelling would be asserting a graph the product does not build.
    /// </remarks>
    public static readonly string[] FlagshipPath =
    [
        "pkg:newtonsoft.json",
        "code:orderapp",
        "task:order_task",
        "iam_role:order_task_role",
        "s3:customer_data",
    ];

    /// <summary>
    /// How many findings each layer should contribute after normalization and dedup.
    /// </summary>
    /// <remarks>
    /// Exact counts rather than "at least one". A harness that asserts non-emptiness passes on
    /// a run that lost two thirds of its findings, which is precisely the silent-degradation
    /// failure the osv.sarif routing bug produced.
    /// </remarks>
    public static readonly IReadOnlyDictionary<string, int> FindingsByLayer =
        new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["Dep"] = 1,     // OSV: Newtonsoft.Json@12.0.1 / CVE-2024-21907
            ["Code"] = 1,    // Roslyn: SCS0028 in OrdersController.cs
            ["Infra"] = 2,   // Checkov: the flagship IAM policy, and the S3 logging finding
        };

    /// <summary>
    /// Each copied file, paired with where the fixture repository keeps its original.
    /// </summary>
    /// <remarks>
    /// Used only by <see cref="FixtureParityTests"/>. The graph inputs are the ones worth
    /// comparing: the SARIF documents here are hand-written stand-ins for scanner output, and
    /// the fixture's own <c>scan_out/</c> is produced by a real scanner run whose line numbers
    /// and rule ids move with the tools' versions.
    /// </remarks>
    public static IReadOnlyDictionary<string, string> FixtureSources =>
        new Dictionary<string, string>(StringComparer.Ordinal)
        {
            // path in this bundle          →  path in sentinelai-fixtures
            ["graph-inputs/infra/main.tf"] = "infra/main.tf",
            ["graph-inputs/infra/iam.tf"] = "infra/iam.tf",
            ["graph-inputs/infra/s3.tf"] = "infra/s3.tf",
            ["graph-inputs/infra/legacy.tf"] = "infra/main.tf",
            ["graph-inputs/src/OrderApp/Dockerfile"] = "src/OrderApp/Dockerfile",
            ["graph-inputs/src/OrderApp/packages.lock.json"] = "src/OrderApp/packages.lock.json",
        };

    /// <summary>The fixture repository root, or null when it is not checked out beside this one.</summary>
    public static string? FixtureRoot => FixtureRepo.Root;
}
