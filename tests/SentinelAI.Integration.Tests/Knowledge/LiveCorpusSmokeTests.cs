using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Application;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure;
using SentinelAI.Infrastructure.Knowledge;

namespace SentinelAI.Integration.Tests.Knowledge;

/// <summary>
/// The end-to-end proof of SEC-22: a real finding, through the real container, answered by the
/// real corpus.
/// </summary>
/// <remarks>
/// <para>
/// Every other test in this suite proves a part. This proves the whole thing is connected — that
/// the configuration actually swaps the retriever, that the adapter reaches Qdrant, and that what
/// comes back is Pipeline A's knowledge rather than the four canned paragraphs the walking
/// skeleton ships with.
/// </para>
/// <para>
/// It reads the corpus location from the environment rather than configuration, so no credential
/// is ever committed:
/// </para>
/// <code>
/// $env:SENTINELAI_CORPUS_URL="https://....cloud.qdrant.io:6334"
/// $env:SENTINELAI_CORPUS_KEY="..."
/// dotnet test tests/SentinelAI.Integration.Tests --filter "FullyQualifiedName~LiveCorpusSmokeTests"
/// </code>
/// <para>
/// It only reads. Unlike <c>QdrantKnowledgeSearchTests</c>, which creates and deletes throwaway
/// collections and must not be pointed at a real corpus, this touches nothing.
/// </para>
/// </remarks>
public class LiveCorpusSmokeTests
{
    private static ServiceProvider Container()
    {
        var settings = new Dictionary<string, string?>
        {
            [$"{QdrantOptions.SectionName}:Endpoint"] = LiveCorpusFactAttribute.Url,
            [$"{QdrantOptions.SectionName}:ApiKey"] = LocalDev.CorpusKey,

            // Deliberately no embedder. The point of this test is that identifier lookups need
            // no model, which is the configuration SEC-22 can be finished in.
            [$"{EmbedderServiceOptions.SectionName}:BaseUrl"] = "",
        };

        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.None));
        services.AddApplicationServices();
        services.AddInfrastructureServices(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());

        return services.BuildServiceProvider();
    }

    /// <summary>A code finding carrying CWE-502 — the fixture's flagship weakness.</summary>
    private static Finding Deserialization() => new()
    {
        Id = Guid.CreateVersion7(),
        SourceTool = "SecurityCodeScan",
        Layer = Layer.Code,
        Severity = 3,
        CweId = "CWE-502",
        CheckId = "SCS0028",
        Location = "src/OrderApp/Controllers/OrdersController.cs:16",
        NodeRef = NodeId.Code("src/OrderApp/Controllers/OrdersController.cs"),
        Message = "Unsafe deserialization of untrusted data in OrderService.",
    };

    [LiveCorpusFact]
    public void The_configured_container_hands_back_the_real_retriever_not_the_stub()
    {
        using var provider = Container();
        using var scope = provider.CreateScope();

        var retriever = scope.ServiceProvider.GetRequiredService<IKnowledgeRetriever>();

        Assert.IsType<KnowledgeRetrievalService>(retriever);
    }

    /// <summary>
    /// The one that matters: a CWE lookup returns the weakness definition from the corpus, and
    /// the source condition keeps the CVEs merely tagged with it out.
    /// </summary>
    [LiveCorpusFact]
    public async Task A_cwe_finding_is_grounded_in_the_real_corpus()
    {
        using var provider = Container();
        using var scope = provider.CreateScope();

        var retriever = scope.ServiceProvider.GetRequiredService<IKnowledgeRetriever>();

        var result = await retriever.RetrieveAsync(Deserialization(), RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(RetrievalMode.ExactFilter, result.Mode);
        Assert.True(result.IsGrounded, "CWE-502 returned nothing — the corpus is empty or the filter is wrong");

        // Every chunk is the weakness itself, never a CVE that merely carries the tag. This is
        // PIPELINE_A_CONTEXT.md §4's 825-versus-2 measurement, against the live corpus.
        Assert.All(result.Chunks, c => Assert.Equal(KnowledgeSource.Cwe, c.Source));
        Assert.Contains(result.Chunks, c => c.ChunkId.StartsWith("cwe-502", StringComparison.Ordinal));
    }

    /// <summary>
    /// What came back has to be Pipeline A's text, not the walking skeleton's. The stub answers
    /// for CWE-502 too, which is exactly why "we got chunks" is not sufficient evidence.
    /// </summary>
    [LiveCorpusFact]
    public async Task What_comes_back_is_the_corpus_and_not_the_canned_stub()
    {
        using var provider = Container();
        using var scope = provider.CreateScope();

        var result = await scope.ServiceProvider.GetRequiredService<IKnowledgeRetriever>()
            .RetrieveAsync(Deserialization(), RetrievalIntent.HowAnAttackerWould);

        foreach (var chunk in result.Chunks)
        {
            // The stub's giveaway: it prefixes every answer with the linking key in brackets and
            // carries no chunk id or corpus version at all.
            Assert.False(chunk.Text.StartsWith("[CWE-502]", StringComparison.Ordinal),
                "this is SeedKnowledgeRetriever's canned text, not the corpus");

            Assert.NotEmpty(chunk.ChunkId);
            Assert.NotEmpty(chunk.Text);
        }

        // A real corpus chunk records which snapshot it came from; the stub has no such concept.
        Assert.Contains(result.Chunks, c => !string.IsNullOrWhiteSpace(c.CorpusVersion));
    }

    /// <summary>
    /// The no-model configuration, end to end: an id-less finding is reported honestly rather
    /// than crashing the scan.
    /// </summary>
    [LiveCorpusFact]
    public async Task An_id_less_finding_reports_the_missing_model_rather_than_failing()
    {
        using var provider = Container();
        using var scope = provider.CreateScope();

        var finding = Deserialization();
        finding.CweId = null;
        finding.CveId = null;

        var result = await scope.ServiceProvider.GetRequiredService<IKnowledgeRetriever>()
            .RetrieveAsync(finding, RetrievalIntent.HowAnAttackerWould);

        Assert.Equal(RetrievalMode.None, result.Mode);
        Assert.Contains(result.Misses, m => m.Reason.Contains("no embedding model", StringComparison.Ordinal));
    }
}

/// <summary>
/// Skips only when this machine has no corpus at all.
/// </summary>
/// <remarks>
/// Resolved by <see cref="LocalDev"/>: an environment variable first, then the developer's own
/// git-ignored <c>appsettings.Development.json</c>. So on a machine configured to run the API
/// against a corpus, these run on a plain <c>dotnet test</c> — no variable to remember. On a
/// fresh clone or in CI they skip, because there is genuinely nothing to test against.
/// </remarks>
public sealed class LiveCorpusFactAttribute : FactAttribute
{
    public LiveCorpusFactAttribute()
    {
        if (string.IsNullOrWhiteSpace(Url))
        {
            Skip = "No corpus configured. Set Knowledge:Endpoint in appsettings.Development.json "
                 + "(or SENTINELAI_CORPUS_URL) to run the live-corpus tests.";
        }
    }

    public static string? Url => LocalDev.CorpusUrl;
}
