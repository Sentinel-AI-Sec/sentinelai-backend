using System.Formats.Tar;
using System.IO.Compression;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Infrastructure.Implementation.Repositories;
using SentinelAI.Infrastructure.Security;

namespace SentinelAI.Infrastructure.Tests.Security;

/// <summary>
/// The gate against a real stored bundle, through the real <see cref="FileSystemBundleStore"/>.
/// </summary>
/// <remarks>
/// Every other gate test stubs the store, which leaves one assumption untested and load-bearing:
/// that the artifacts the gate wants are the ones the store actually hands back. If
/// <c>OpenGraphInputsAsync</c> ever filtered by extension — a plausible optimization, since the
/// graph seams only read <c>.tf</c>, lock files and Dockerfiles — the fixture's Dockerfile secret
/// would stop being scanned in production while all the stubbed tests carried on passing.
/// </remarks>
public class IngressGateRealBundleTests
{
    [Fact]
    public async Task Finds_the_fixture_secret_in_a_real_stored_bundle()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sentinelai-tests", Guid.NewGuid().ToString());
        Directory.CreateDirectory(dir);
        var locator = Path.Combine(dir, "bundle.tar.gz");

        try
        {
            // The reference fixture's own layout, including its INFRA-07 Dockerfile secret.
            await WriteTarGz(locator, new Dictionary<string, string>
            {
                ["metadata.json"] = "{}",
                ["findings/checkov_docker.sarif"] = "{\"runs\":[]}",
                ["graph-inputs/Dockerfile"] =
                    "FROM base\nWORKDIR /app\n"
                    + "ENV ORDER_SVC_API_KEY=\"demo-fixture-dummy-key-not-real-000111\"\n"
                    + "ENTRYPOINT [\"dotnet\", \"OrderApp.dll\"]\n",
                ["graph-inputs/infra/iam.tf"] =
                    "resource \"aws_iam_role\" \"order_task_role\" {\n  name = \"order-task-role\"\n}\n",
                ["graph-inputs/src/OrderApp/packages.lock.json"] = "{\"version\":1}",
            });

            var store = new FileSystemBundleStore(
                Options.Create(new BundleStorageOptions()), NullLogger<FileSystemBundleStore>.Instance);

            var gate = new IngressRedactionGate(
                new RegexSecretScanner(), store, NullLogger<IngressRedactionGate>.Instance);

            var result = await gate.ApplyAsync(
                locator, [], Guid.CreateVersion7(), Guid.CreateVersion7());

            // All three graph-inputs entries reached the gate — including the lock file, which
            // no secret rule cares about. The gate sees everything the runner shipped, not a
            // subset chosen by what some other stage needs.
            Assert.Equal(3, result.ArtifactsScanned);

            var secret = Assert.Single(result.Findings);
            Assert.Equal(ScannerNames.IngressGate, secret.SourceTool);
            Assert.Equal(IngressRedactionGate.SecretSeverity, secret.Severity);
            Assert.Equal("Dockerfile:3", secret.Location);
            Assert.DoesNotContain(
                "demo-fixture-dummy-key-not-real-000111", secret.Message, StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    private static async Task WriteTarGz(string path, IReadOnlyDictionary<string, string> entries)
    {
        await using var file = File.Create(path);
        await using var gzip = new GZipStream(file, CompressionLevel.Fastest);
        await using var tar = new TarWriter(gzip);

        foreach (var (name, content) in entries)
        {
            await tar.WriteEntryAsync(new PaxTarEntry(TarEntryType.RegularFile, name)
            {
                DataStream = new MemoryStream(Encoding.UTF8.GetBytes(content)),
            });
        }
    }
}
