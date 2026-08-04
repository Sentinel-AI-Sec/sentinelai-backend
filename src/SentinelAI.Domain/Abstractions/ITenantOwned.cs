namespace SentinelAI.Domain.Abstractions;

/// <summary>
/// Marks an entity as belonging to exactly one tenant. <see cref="SentinelDbContext"/>
/// (Infrastructure) applies a tenant query filter to every entity implementing this
/// interface automatically, by reflection, in <c>OnModelCreating</c> — a new tenant-owned
/// entity is isolated the moment it implements this, with no query, repository, or config
/// class to remember (SEC-32: "one forgotten query is a data leak").
/// </summary>
/// <remarks>
/// Set once, at creation, from the caller's verified token — never from anything the
/// caller typed. <see cref="Models.RuleMapping"/> deliberately does not implement this: it
/// is shared reference data, not owned by any tenant.
/// </remarks>
public interface ITenantOwned
{
    Guid TenantId { get; set; }
}
