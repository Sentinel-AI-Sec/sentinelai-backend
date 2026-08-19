using Microsoft.AspNetCore.Identity;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

/// <summary>
/// Wraps ASP.NET Core's own <see cref="PasswordHasher{TUser}"/> — PBKDF2, versioned work
/// factor, the same code Identity itself uses — rather than pulling in a third-party
/// library or rolling anything custom.
/// </summary>
public sealed class PasswordHasher : IPasswordHasher
{
    // The framework type is generic per-user for extensibility hooks the default PBKDF2
    // implementation never actually uses; passing null is the standard way to use it
    // without needing per-user customization.
    private readonly PasswordHasher<User> _hasher = new();

    public string Hash(string password) => _hasher.HashPassword(null!, password);

    public bool Verify(string hash, string password) =>
        _hasher.VerifyHashedPassword(null!, hash, password) is
            PasswordVerificationResult.Success or PasswordVerificationResult.SuccessRehashNeeded;
}
