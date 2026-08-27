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

    /// <summary>
    /// How many users a tenant holds, and how many of those are admins.
    /// </summary>
    /// <remarks>
    /// The second exception to the tenant filter, and it exists for the same structural reason as
    /// the first: the tenant being counted is deliberately <em>not</em> the caller's. Moving an
    /// account into a tenant has to know what its current tenant would be left with — nobody at
    /// all, in which case that tenant is purged, or other members who would be stranded with no
    /// admin, in which case the move is refused. Neither question can be asked through the
    /// filtered repository, which can only ever see the caller's own tenant.
    /// </remarks>
    Task<TenantMembership> CountMembersAsync(Guid tenantId, CancellationToken ct = default);
}

/// <summary>What a tenant's user list consists of.</summary>
/// <param name="Total">Every user in the tenant, admins included.</param>
/// <param name="Admins">How many of them hold <see cref="Roles.Admin"/>.</param>
public sealed record TenantMembership(int Total, int Admins);
