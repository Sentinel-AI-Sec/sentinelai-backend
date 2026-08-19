using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Infrastructure.Implementation.Repositories;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// SEC-13's core privacy promise: a bundle carrying application source is refused, and a
/// clean bundle is accepted. <see cref="TarGzBundleInspector"/> is exercised directly,
/// against real tar.gz bytes, rather than through fakes.
/// </summary>
public class BundleIngestTests
{
    private static TarGzBundleInspector CreateInspector() =>
        new(NullLogger<TarGzBundleInspector>.Instance);

    [Fact]
    public async Task Valid_bundle_is_accepted()
    {
        var inspector = CreateInspector();
        await using var bundle = TarGzTestHelper.ValidBundle();

        var result = await inspector.InspectAsync(bundle, CancellationToken.None);

        Assert.True(result.IsValid, result.Error);
        Assert.Contains("metadata.json", result.Entries);
        Assert.Contains("findings/osv.sarif", result.Entries);
        Assert.NotNull(result.MetadataJson);
        Assert.NotEmpty(result.Sha256);
        Assert.NotNull(result.RawBundle);

        // The buffer handed back is a faithful, rewound copy of what was inspected — the
        // bundle store reads from this rather than the original stream.
        Assert.Equal(0, result.RawBundle!.Position);
        Assert.True(result.RawBundle.Length > 0);
    }

    [Fact]
    public async Task Bundle_containing_a_cs_file_is_rejected()
    {
        var inspector = CreateInspector();
        await using var bundle = TarGzTestHelper.Build(new Dictionary<string, string>
        {
            ["metadata.json"] = """{"project_id":"11111111-1111-1111-1111-111111111111","commit_sha":"abc123"}""",
            ["findings/osv.sarif"] = "{}",
            ["src/Program.cs"] = "class Program {}",
        });

        var result = await inspector.InspectAsync(bundle, CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Contains("application source", result.Error);
        Assert.Empty(result.Entries);
        Assert.Null(result.RawBundle);
    }

    [Fact]
    public async Task Bundle_with_no_findings_directory_is_rejected()
    {
        var inspector = CreateInspector();
        await using var bundle = TarGzTestHelper.Build(new Dictionary<string, string>
        {
            ["metadata.json"] = """{"project_id":"11111111-1111-1111-1111-111111111111","commit_sha":"abc123"}""",
        });

        var result = await inspector.InspectAsync(bundle, CancellationToken.None);

        Assert.False(result.IsValid);
        Assert.Contains("findings/", result.Error);
    }
}
