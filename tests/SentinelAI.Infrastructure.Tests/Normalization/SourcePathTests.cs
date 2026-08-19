using SentinelAI.Infrastructure.Normalization;

namespace SentinelAI.Infrastructure.Tests.Normalization;

/// <summary>
/// The standing B7 hazard: Roslyn and OSV bake the build agent's absolute path into their
/// SARIF. That path reaches the dedup key and the node reference, so if it survives
/// un-normalized the same finding scanned on two machines becomes two findings on two nodes —
/// and nothing errors.
/// </summary>
public class SourcePathTests
{
    [Theory]
    // The exact shape in the committed fixture's roslyn.sarif.
    [InlineData(
        "file:///C:/Users/PC_STORE/Downloads/sentinelai-fixture_2/sentinelai-fixture/src/OrderApp/Controllers/OrdersController.cs",
        "src/OrderApp/Controllers/OrdersController.cs")]
    [InlineData(
        "file:///C:/Users/PC_STORE/Downloads/sentinelai-fixture_2/sentinelai-fixture/src/OrderApp/packages.lock.json",
        "src/OrderApp/packages.lock.json")]
    // A Linux runner's checkout.
    [InlineData("file:///home/runner/work/repo/repo/infra/iam.tf", "infra/iam.tf")]
    // Already repo-relative: left alone.
    [InlineData("infra/iam.tf", "infra/iam.tf")]
    [InlineData("Dockerfile", "Dockerfile")]
    [InlineData("src/OrderApp/bin/Debug/net8.0/OrderApp.deps.json", "src/OrderApp/bin/Debug/net8.0/OrderApp.deps.json")]
    // Percent-encoding and backslashes.
    [InlineData("file:///C:/build%20dir/repo/src/App/A.cs", "src/App/A.cs")]
    [InlineData("C:\\repo\\src\\App\\A.cs", "src/App/A.cs")]
    // No recognizable project root: degrade to the file name, which is at least the same on
    // every machine. Better a coarse key than one carrying somebody's home directory.
    [InlineData("file:///C:/Users/PC_STORE/scratch/Program.cs", "Program.cs")]
    public void Normalizes_to_a_repo_relative_path(string uri, string expected)
        => Assert.Equal(expected, SourcePath.Normalize(uri));

    [Fact]
    public void The_same_file_from_two_machines_normalizes_to_one_path()
    {
        const string windows = "file:///C:/Users/PC_STORE/Downloads/fixture/src/OrderApp/Controllers/OrdersController.cs";
        const string linux = "file:///home/runner/work/sentinelai-fixture/src/OrderApp/Controllers/OrdersController.cs";

        Assert.Equal(SourcePath.Normalize(windows), SourcePath.Normalize(linux));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Nothing_usable_is_null_rather_than_an_empty_key(string? uri)
        => Assert.Null(SourcePath.Normalize(uri));

    [Fact]
    public void Appends_the_line_when_the_tool_reported_one()
        => Assert.Equal("infra/iam.tf:25", SourcePath.WithLine("infra/iam.tf", 25));

    [Theory]
    [InlineData(null)]
    [InlineData(0)]
    public void Omits_a_line_the_tool_did_not_report(int? line)
        => Assert.Equal("infra/iam.tf", SourcePath.WithLine("infra/iam.tf", line));
}
