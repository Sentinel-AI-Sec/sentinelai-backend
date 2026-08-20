using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using SentinelAI.Domain.Models;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.Regression;

/// <summary>
/// SEC-44: the archive <c>scripts/demo.sh</c> and <c>scripts/demo.ps1</c> produce is one the
/// ingest endpoint accepts, and the chain still comes out of it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is not already covered by the regression harness.</b> The harness packs the same
/// <em>files</em>, but through <c>TarWriter</c>, which writes one plain entry per file. The two
/// demo drivers shell out to <c>tar</c>, and <c>tar -czf archive.tar.gz .</c> writes something
/// different: every path is prefixed <c>./</c>, and every directory gets an entry of its own
/// ending in a slash. Six extra entries that are not files, and a leading <c>./</c> on the
/// twelve that are.
/// </para>
/// <para>
/// Both are legitimate tar. Whether the ingest path treats them the same is a property of
/// <c>TarGzBundleInspector</c>, <c>BundleContentPolicy</c> and <c>FileSystemBundleStore</c>
/// agreeing on normalisation — three components, each of which normalises separately. That is a
/// seam, and the demo is exactly where a seam defect is most expensive: five minutes before a
/// presentation, on a bundle that packs cleanly and is refused with a 422 nobody can read.
/// </para>
/// <para>
/// So the archive here is built the way <c>tar</c> builds it, not the way the harness does.
/// </para>
/// </remarks>
public class DemoBundleTests(ScanApiFactory factory) : IClassFixture<ScanApiFactory>
{
    private static readonly Guid Tenant = Guid.NewGuid();

    /// <summary>
    /// Packs the golden bundle the way <c>tar -czf bundle.tar.gz .</c> does.
    /// </summary>
    /// <remarks>
    /// Directory entries first and in path order, each name prefixed <c>./</c> — the shape GNU
    /// tar and bsdtar both produce, and the one neither demo driver can avoid producing.
    /// </remarks>
    private static byte[] TarCliStyle(Guid projectId)
    {
        var files = GoldenBundle.Files(projectId, "demo-shape");

        var directories = files.Keys
            .SelectMany(path => Ancestors(path))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(path => path, StringComparer.Ordinal)
            .ToList();

        var archive = new MemoryStream();

        using (var gzip = new GZipStream(archive, CompressionLevel.Fastest, leaveOpen: true))
        using (var tar = new TarWriter(gzip, leaveOpen: false))
        {
            // The archive root itself, which `tar … .` always writes first.
            tar.WriteEntry(new PaxTarEntry(TarEntryType.Directory, "./"));

            foreach (var directory in directories)
                tar.WriteEntry(new PaxTarEntry(TarEntryType.Directory, $"./{directory}/"));

            foreach (var (name, content) in files.OrderBy(f => f.Key, StringComparer.Ordinal))
            {
                tar.WriteEntry(new PaxTarEntry(TarEntryType.RegularFile, $"./{name}")
                {
                    DataStream = new MemoryStream(Encoding.UTF8.GetBytes(content)),
                });
            }
        }

        return archive.ToArray();
    }

    /// <summary>Every directory a path sits under, e.g. <c>a/b/c.txt</c> → <c>a</c>, <c>a/b</c>.</summary>
    private static IEnumerable<string> Ancestors(string path)
    {
        var parts = path.Split('/');

        for (var i = 1; i < parts.Length; i++)
            yield return string.Join('/', parts[..i]);
    }

    private async Task<Guid> SeedProjectAsync()
    {
        var projectId = Guid.CreateVersion7();

        await factory.SeedAsync(db => db.Projects.Add(new Project
        {
            Id = projectId,
            TenantId = Tenant,
            RepoUrl = $"https://example.test/demo/{projectId}",
            DefaultBranch = "main",
        }));

        return projectId;
    }

    private HttpClient Client()
    {
        var client = factory.CreateClient();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            TestJwt.Create(Tenant, Guid.NewGuid(), Roles.Analyst,
                [AuthScopes.ScanWrite, AuthScopes.ScanRead, AuthScopes.ReportRead]));

        return client;
    }

    /// <summary>
    /// The demo drivers' archive is accepted, and the flagship chain comes out of it.
    /// </summary>
    /// <remarks>
    /// Driven through the graph stage rather than stopping at the 202, because "the bundle was
    /// accepted" and "the bundle's files were found inside it" are different claims. Directory
    /// entries and a <c>./</c> prefix could pass ingest and still leave the store matching
    /// nothing under <c>findings/</c> — a scan that ingests cleanly and then reports zero
    /// findings, which is the failure that looks exactly like a clean repository.
    /// </remarks>
    [Fact]
    public async Task The_archive_the_demo_scripts_produce_is_accepted_and_yields_the_flagship_chain()
    {
        var projectId = await SeedProjectAsync();
        var bundle = TarCliStyle(projectId);

        using var client = Client();

        var form = new MultipartFormDataContent
        {
            { new StringContent(GoldenBundle.MetadataJson(projectId, "demo-shape")), "metadata" },
        };

        var file = new ByteArrayContent(bundle);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/gzip");
        form.Add(file, "bundle", "bundle.tar.gz");

        using var submit = await client.PostAsync("/v1/scans", form);
        var submitBody = await submit.Content.ReadAsStringAsync();

        Assert.True(
            submit.StatusCode == HttpStatusCode.Accepted,
            $"the demo drivers' archive shape was refused: {(int)submit.StatusCode} {submitBody}");

        using var submitted = JsonDocument.Parse(submitBody);
        var scanJobId = submitted.RootElement.GetProperty("data").GetProperty("scanJobId").GetString();

        using var graph = await client.PostAsync($"/v1/scans/{scanJobId}/graph", content: null);
        var graphBody = await graph.Content.ReadAsStringAsync();

        Assert.True(
            graph.StatusCode == HttpStatusCode.OK,
            $"the graph stage refused the demo drivers' bundle: {(int)graph.StatusCode} {graphBody}");

        using var graphed = JsonDocument.Parse(graphBody);
        var data = graphed.RootElement.GetProperty("data");

        // The findings were found inside an archive whose every path carries a ./ prefix.
        Assert.Equal(4, data.GetProperty("findings").GetInt32());

        var paths = data.GetProperty("chains").EnumerateArray()
            .Select(chain => chain.GetProperty("path").EnumerateArray().Select(p => p.GetString()!).ToList())
            .ToList();

        Assert.True(
            paths.Any(path => path.SequenceEqual(GoldenBundle.FlagshipPath)),
            "the flagship chain is not among the candidates from the demo drivers' archive shape. "
            + $"Found: {string.Join(" | ", paths.Select(p => string.Join(" -> ", p)))}");
    }

    /// <summary>
    /// The three entries both demo drivers assert on before uploading really are in the bundle.
    /// </summary>
    /// <remarks>
    /// The scripts check these locally so a packing mistake is caught before an audience sees
    /// it. That check is only worth having if the names it looks for are the names the layout
    /// allowlist wants — <c>terraform-graph.dot</c>, not <c>terraform.dot</c>, which is refused
    /// with a 422. This is the test that keeps the two lists in step.
    /// </remarks>
    [Theory]
    [InlineData("metadata.json")]
    [InlineData("scanner-versions.json")]
    [InlineData("findings/osv.sarif")]
    [InlineData("findings/roslyn.sarif")]
    [InlineData("findings/checkov.sarif")]
    [InlineData("graph-inputs/terraform-graph.dot")]
    [InlineData("graph-inputs/infra/iam.tf")]
    [InlineData("graph-inputs/src/OrderApp/Dockerfile")]
    [InlineData("graph-inputs/src/OrderApp/packages.lock.json")]
    public void The_golden_bundle_contains_every_entry_the_demo_scripts_expect(string path)
    {
        Assert.Contains(path, GoldenBundle.Files(Guid.NewGuid(), "check").Keys);
    }

    /// <summary>
    /// The bundle's own README is not packed.
    /// </summary>
    /// <remarks>
    /// It is documentation for a human opening the directory, and the layout allowlist refuses
    /// it — correctly, since the collector does not produce it. Both drivers exclude it, and so
    /// does <c>GoldenBundle.Files</c>; this is the assertion that keeps all three in agreement
    /// after somebody adds a second markdown file.
    /// </remarks>
    [Fact]
    public void Documentation_in_the_bundle_directory_is_not_packed()
    {
        Assert.DoesNotContain(
            GoldenBundle.Files(Guid.NewGuid(), "check").Keys,
            name => name.EndsWith(".md", StringComparison.OrdinalIgnoreCase));
    }
}
