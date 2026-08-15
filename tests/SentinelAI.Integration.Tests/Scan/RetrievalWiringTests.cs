using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SentinelAI.Application.Abstractions;
using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Application;
using SentinelAI.Infrastructure;
using SentinelAI.Infrastructure.Knowledge;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// SEC-22's swap: whether a scan is grounded in the real corpus or in canned text is decided by
/// configuration, and this is the test that says which one you actually got.
/// </summary>
/// <remarks>
/// <para>
/// Every other SEC-22 test proves the decision tree behaves. None of them would fail if
/// <c>AddInfrastructureServices</c> quietly registered the stub instead — and that failure is
/// invisible in exactly the way this codebase cares about: the scan completes, the debate runs,
/// the report cites chunks, and every one of those chunks came from a four-entry dictionary.
/// </para>
/// <para>
/// So this boots the real container against real configuration and asks which implementation
/// came back. It needs no Qdrant and no embedder — it is asserting the <em>decision</em>, not the
/// connection, so it runs in CI where neither exists.
/// </para>
/// </remarks>
public class RetrievalWiringTests
{
    /// <summary>
    /// The app's own registration, over an in-memory configuration.
    /// </summary>
    /// <remarks>
    /// Both layers, in the order <c>Program.cs</c> composes them. Registering only Infrastructure
    /// would leave SEC-21's query builder unresolvable and fail this test for a reason that has
    /// nothing to do with the swap it is meant to be checking.
    /// </remarks>
    private static ServiceProvider Container(Dictionary<string, string?> settings)
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(settings)
            .Build();

        var services = new ServiceCollection();
        services.AddLogging(b => b.SetMinimumLevel(LogLevel.None));
        services.AddApplicationServices();
        services.AddInfrastructureServices(configuration);

        return services.BuildServiceProvider();
    }

    /// <summary>Corpus endpoint plus embedder URL — the configuration that turns SEC-22 on.</summary>
    private static Dictionary<string, string?> CorpusConfigured() => new()
    {
        [$"{QdrantOptions.SectionName}:Endpoint"] = "http://localhost:6334",
        [$"{EmbedderServiceOptions.SectionName}:BaseUrl"] = "http://localhost:7860",
    };

    [Fact]
    public void With_a_corpus_and_an_embedder_the_real_decision_tree_answers()
    {
        using var provider = Container(CorpusConfigured());
        using var scope = provider.CreateScope();

        var retriever = scope.ServiceProvider.GetRequiredService<IKnowledgeRetriever>();

        Assert.IsType<KnowledgeRetrievalService>(retriever);
    }

    /// <summary>
    /// The default for a fresh clone. Not a defect — the exact-filter arm needs no corpus — but it
    /// must be the canned stub and not something that looks real.
    /// </summary>
    [Fact]
    public void With_nothing_configured_the_canned_stub_answers()
    {
        using var provider = Container([]);
        using var scope = provider.CreateScope();

        Assert.IsType<SeedKnowledgeRetriever>(scope.ServiceProvider.GetRequiredService<IKnowledgeRetriever>());
    }

    /// <summary>
    /// A corpus with no embedder is a supported deployment, not a degraded one.
    /// </summary>
    /// <remarks>
    /// Looking up CWE-502 by its id is a payload filter with no vector in it, so an
    /// identifier-carrying finding grounds for real whether or not a model exists. Falling back
    /// to the canned stub here would replace real knowledge with invented text for every finding
    /// — strictly worse than answering the ones we can.
    /// </remarks>
    [Fact]
    public void A_corpus_without_an_embedder_still_uses_the_real_decision_tree()
    {
        using var provider = Container(new Dictionary<string, string?>
        {
            [$"{QdrantOptions.SectionName}:Endpoint"] = "http://localhost:6334",
        });
        using var scope = provider.CreateScope();

        Assert.IsType<KnowledgeRetrievalService>(
            scope.ServiceProvider.GetRequiredService<IKnowledgeRetriever>());

        // ...and the embedder is the one that reports itself unavailable, so the meaning-based
        // arms report a miss rather than throwing mid-scan.
        Assert.False(scope.ServiceProvider.GetRequiredService<IQueryEmbedder>().IsAvailable);
    }

    /// <summary>An embedder with no corpus has nothing to search, so the stub still answers.</summary>
    [Fact]
    public void An_embedder_without_a_corpus_falls_back_to_the_stub()
    {
        using var provider = Container(new Dictionary<string, string?>
        {
            [$"{EmbedderServiceOptions.SectionName}:BaseUrl"] = "http://localhost:7860",
        });
        using var scope = provider.CreateScope();

        Assert.IsType<SeedKnowledgeRetriever>(
            scope.ServiceProvider.GetRequiredService<IKnowledgeRetriever>());
    }

    /// <summary>
    /// The tree's own dependencies have to resolve, or the swap above would throw at first use
    /// rather than at startup.
    /// </summary>
    [Fact]
    public void The_configured_container_can_build_every_part_of_the_tree()
    {
        using var provider = Container(CorpusConfigured());
        using var scope = provider.CreateScope();

        Assert.NotNull(scope.ServiceProvider.GetRequiredService<KnowledgeRetrievalService>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IKnowledgeSearch>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<IQueryEmbedder>());
        Assert.NotNull(scope.ServiceProvider.GetRequiredService<RetrievalQueryBuilder>());
    }

    /// <summary>
    /// With no embedder configured the embedder must be the one that refuses, never a stub that
    /// returns arbitrary vectors — those would ground the debate in near-random chunks and report
    /// success.
    /// </summary>
    [Fact]
    public async Task An_unconfigured_embedder_refuses_rather_than_inventing_vectors()
    {
        using var provider = Container([]);
        using var scope = provider.CreateScope();

        var embedder = scope.ServiceProvider.GetRequiredService<IQueryEmbedder>();

        Assert.IsType<NotConfiguredQueryEmbedder>(embedder);
        await Assert.ThrowsAsync<InvalidOperationException>(() => embedder.EmbedAsync("anything"));
    }
}
