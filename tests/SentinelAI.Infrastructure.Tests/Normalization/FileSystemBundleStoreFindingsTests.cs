using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelAI.Infrastructure.Implementation.Repositories;

namespace SentinelAI.Infrastructure.Tests.Normalization;

/// <summary>
/// Proves the "use IBundleStore's locator" seam the pipeline depends on: given the locator
/// SaveAsync produced, OpenFindingsAsync hands back exactly the findings files and nothing else.
/// </summary>
public class FileSystemBundleStoreFindingsTests
{
    [Fact]
    public async Task Returns_only_the_findings_files_from_the_stored_tarball()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sentinelai-tests", Guid.NewGuid().ToString());
        Directory.CreateDirectory(dir);
        var locator = Path.Combine(dir, "bundle.tar.gz");

        try
        {
            await WriteTarGz(locator, new Dictionary<string, string>
            {
                ["findings/roslyn.sarif"] = "{\"runs\":[]}",
                ["findings/osv.json"] = "{\"results\":[]}",
                ["graph-inputs/main.tf"] = "resource \"aws_s3_bucket\" \"x\" {}",  // excluded
                ["metadata.json"] = "{}",                                          // excluded
            });

            var store = new FileSystemBundleStore(
                Options.Create(new BundleStorageOptions()), NullLogger<FileSystemBundleStore>.Instance);

            var files = await store.OpenFindingsAsync(locator, CancellationToken.None);

            Assert.Equal(2, files.Count);
            Assert.Contains(files, f => f.Name == "findings/roslyn.sarif");
            Assert.Contains(files, f => f.Name == "findings/osv.json");
            Assert.DoesNotContain(files, f => f.Name.StartsWith("graph-inputs"));
            Assert.DoesNotContain(files, f => f.Name == "metadata.json");

            var osv = files.Single(f => f.Name == "findings/osv.json");
            Assert.Equal("{\"results\":[]}", Encoding.UTF8.GetString(osv.Content));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task A_missing_locator_yields_no_findings_rather_than_throwing()
    {
        var store = new FileSystemBundleStore(
            Options.Create(new BundleStorageOptions()), NullLogger<FileSystemBundleStore>.Instance);

        var files = await store.OpenFindingsAsync(
            Path.Combine(Path.GetTempPath(), $"nope-{Guid.NewGuid()}.tar.gz"), CancellationToken.None);

        Assert.Empty(files);
    }

    [Fact]
    public async Task Returns_only_the_graph_input_files_from_the_stored_tarball()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sentinelai-tests", Guid.NewGuid().ToString());
        Directory.CreateDirectory(dir);
        var locator = Path.Combine(dir, "bundle.tar.gz");

        try
        {
            await WriteTarGz(locator, new Dictionary<string, string>
            {
                ["graph-inputs/terraform-graph.dot"] = "digraph G {}",
                ["graph-inputs/infra/main.tf"] = "resource \"aws_s3_bucket\" \"x\" {}",
                ["findings/roslyn.sarif"] = "{\"runs\":[]}",  // excluded
                ["metadata.json"] = "{}",                     // excluded
            });

            var store = new FileSystemBundleStore(
                Options.Create(new BundleStorageOptions()), NullLogger<FileSystemBundleStore>.Instance);

            var files = await store.OpenGraphInputsAsync(locator, CancellationToken.None);

            Assert.Equal(2, files.Count);
            Assert.Contains(files, f => f.Name == "graph-inputs/terraform-graph.dot");
            Assert.Contains(files, f => f.Name == "graph-inputs/infra/main.tf");
            Assert.DoesNotContain(files, f => f.Name.StartsWith("findings"));
            Assert.DoesNotContain(files, f => f.Name == "metadata.json");
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static async Task WriteTarGz(string path, Dictionary<string, string> entries)
    {
        await using var file = File.Create(path);
        await using var gzip = new GZipStream(file, CompressionLevel.Optimal);
        await using var tar = new TarWriter(gzip, TarEntryFormat.Pax);

        foreach (var (name, content) in entries)
        {
            var entry = new PaxTarEntry(TarEntryType.RegularFile, name)
            {
                DataStream = new MemoryStream(Encoding.UTF8.GetBytes(content)),
            };
            await tar.WriteEntryAsync(entry);
        }
    }
}
