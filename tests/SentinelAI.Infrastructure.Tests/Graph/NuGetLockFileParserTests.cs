using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>
/// SEC-18 part A, step 1: reading NuGet's <c>packages.lock.json</c> shape into a flat package
/// list, direct and transitive alike.
/// </summary>
public class NuGetLockFileParserTests
{
    private const string LockFile = """
        {
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Newtonsoft.Json": {
                "type": "Direct",
                "requested": "[13.0.3, )",
                "resolved": "13.0.3",
                "contentHash": "hA8s6q4kgQ4wxGdg=="
              },
              "Microsoft.Extensions.Logging.Abstractions": {
                "type": "Transitive",
                "resolved": "8.0.0",
                "contentHash": "hA8s6q4kgQ4wxGdg=="
              }
            }
          }
        }
        """;

    [Fact]
    public void Reads_both_direct_and_transitive_packages()
    {
        var packages = NuGetLockFileParser.Parse(LockFile);

        Assert.Equal(2, packages.Count);

        var direct = Assert.Single(packages, p => p.Name == "Newtonsoft.Json");
        Assert.Equal("13.0.3", direct.Version);
        Assert.True(direct.IsDirect);

        var transitive = Assert.Single(packages, p => p.Name == "Microsoft.Extensions.Logging.Abstractions");
        Assert.Equal("8.0.0", transitive.Version);
        Assert.False(transitive.IsDirect);
    }

    [Fact]
    public void One_package_across_two_target_frameworks_becomes_one_entry()
    {
        const string multiTfm = """
            {
              "version": 1,
              "dependencies": {
                "net8.0": { "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.3" } },
                "net9.0": { "Newtonsoft.Json": { "type": "Direct", "resolved": "13.0.3" } }
              }
            }
            """;

        var packages = NuGetLockFileParser.Parse(multiTfm);

        Assert.Single(packages);
    }

    [Fact]
    public void No_dependencies_object_yields_an_empty_list()
    {
        var packages = NuGetLockFileParser.Parse("""{ "version": 1 }""");

        Assert.Empty(packages);
    }

    [Fact]
    public void Blank_input_yields_an_empty_list()
    {
        Assert.Empty(NuGetLockFileParser.Parse(""));
    }
}
