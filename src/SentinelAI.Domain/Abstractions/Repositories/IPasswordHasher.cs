namespace SentinelAI.Domain.Abstractions.Repositories;

/// <summary>Hashes and verifies passwords. Never store or compare a raw password
/// anywhere — this is the only place that's allowed to touch one.</summary>
public interface IPasswordHasher
{
    string Hash(string password);

    bool Verify(string hash, string password);
}
