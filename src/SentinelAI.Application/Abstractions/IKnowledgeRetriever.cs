namespace SentinelAI.Application.Abstractions;

// Application says WHAT it needs; Infrastructure (Qdrant) says HOW.
public interface IKnowledgeRetriever
{
    Task<IReadOnlyList<string>> RetrieveAsync(
        string query, string collection, CancellationToken ct = default);
}
