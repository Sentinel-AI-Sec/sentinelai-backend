using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Infrastructure.Normalization;

namespace SentinelAI.Infrastructure.Tests.Normalization;

public class NormalizationPipelineTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private static NormalizationPipeline Build(IBundleStore store)
    {
        IFindingExtractor[] extractors =
        [
            new RoslynSarifExtractor(),
            new OsvJsonExtractor(),
            new TrivySarifExtractor(),
            new CheckovSarifExtractor(),
        ];

        return new NormalizationPipeline(extractors, store, NullLogger<NormalizationPipeline>.Instance);
    }

    [Fact]
    public async Task Combines_every_tools_findings_and_tags_each_layer()
    {
        var store = new StubBundleStore
        {
            // roslyn: 1 code | osv: 2 dep | trivy: 1 dep + 1 infra | checkov x2: 3 infra
            ["findings/roslyn.sarif"] = Fixtures.RoslynSarifV2,
            ["findings/osv.json"] = Fixtures.OsvNativeJson,
            ["findings/trivy.sarif"] = Fixtures.TrivySarifV2,
            ["findings/checkov_infra.sarif"] = Fixtures.CheckovSarifV1,   // 2 infra
            ["findings/checkov_docker.sarif"] = SingleCheckovResult,      // 1 infra
            // Deliberately ignored: OSV is read as native JSON, never as SARIF, and metadata is
            // not a findings file. Neither must add to the count.
            ["findings/osv.sarif"] = Fixtures.TrivySarifV2,
            ["metadata.json"] = "{}",
        };

        var findings = await Build(store).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

        Assert.Equal(8, findings.Count);
        Assert.Equal(1, findings.Count(f => f.Layer == Layer.Code));
        Assert.Equal(3, findings.Count(f => f.Layer == Layer.Dep));
        Assert.Equal(4, findings.Count(f => f.Layer == Layer.Infra));

        // Every finding is stamped and left ready for the graph stage.
        Assert.All(findings, f => Assert.Equal(Job, f.ScanJobId));
        Assert.All(findings, f => Assert.False(string.IsNullOrEmpty(f.SourceTool)));
        Assert.All(findings, f => Assert.Equal(string.Empty, f.NodeRef));
    }

    [Fact]
    public async Task One_malformed_file_does_not_sink_the_others()
    {
        var store = new StubBundleStore
        {
            ["findings/roslyn.sarif"] = Fixtures.RoslynSarifV2,   // 1 code
            ["findings/trivy.sarif"] = Fixtures.InvalidJson,      // throws, skipped
        };

        var findings = await Build(store).NormalizeAsync("loc", Tenant, Job, CancellationToken.None);

        var only = Assert.Single(findings);
        Assert.Equal(Layer.Code, only.Layer);
    }

    // A one-result Checkov SARIF v2, so the two Checkov files in the pipeline contribute a
    // distinct number of findings (2 + 1) rather than the same fixture twice.
    private const string SingleCheckovResult = """
    {
      "version": "2.1.0",
      "runs": [
        {
          "tool": { "driver": { "name": "Checkov", "rules": [] } },
          "results": [
            { "ruleId": "CKV_DOCKER_3", "level": "warning", "message": { "text": "Image runs as root." } }
          ]
        }
      ]
    }
    """;

    private sealed class StubBundleStore : Dictionary<string, string>, IBundleStore
    {
        public Task<IReadOnlyList<StoredBundleFile>> OpenFindingsAsync(string locator, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<StoredBundleFile>>(
                this.Select(kv => new StoredBundleFile(kv.Key, Encoding.UTF8.GetBytes(kv.Value))).ToList());

        public Task<string> SaveAsync(Guid scanJobId, Stream bundle, CancellationToken ct)
            => throw new NotSupportedException();

        public Task PurgeAsync(Guid scanJobId, CancellationToken ct) => throw new NotSupportedException();
    }
}
