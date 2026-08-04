using SentinelAI.Domain.Models;

namespace SentinelAI.Domain.Abstractions.Repositories;

/// <summary>Identity lookups that deliberately fall outside SEC-32's tenant query filter.</summary>
public interface IUserRepository
{
    /// <summary>
    /// Looks up a user by email across every tenant. This is the one legitimate exception
    /// to tenant isolation in the whole codebase: at login/registration time we don't know
    /// the caller's tenant yet — figuring that out is the entire point of this lookup. Every
    /// other query in the system stays scoped by the automatic filter; this one can't be,
    /// by definition, and says so.
    /// </summary>
    Task<User?> GetByEmailAsync(string email, CancellationToken ct = default);
}
