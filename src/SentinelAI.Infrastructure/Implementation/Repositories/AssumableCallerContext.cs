using Microsoft.AspNetCore.Http;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

/// <summary>
/// The caller for a scope that may not have an HTTP request: claims when there is one, and an
/// explicitly assumed tenant when there is not (SEC-46).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the worker needs this at all.</b> <c>SentinelDbContext</c> reads
/// <see cref="ICallerContext.TenantId"/> in its constructor and hangs
/// <c>e.TenantId == CurrentTenantId</c> on every <see cref="Domain.Abstractions.ITenantOwned"/>
/// entity — twelve of the fourteen tables, including findings, graph nodes, edges and chains. A
/// background service has no <c>HttpContext</c>, so without this the filter resolves to
/// <c>Guid.Empty</c> and every read in the pipeline returns nothing. Writes are unaffected by
/// query filters, so the failure is silent: the worker would persist findings, read back none,
/// build zero chains, and complete successfully with a report saying the scan was clean.
/// </para>
/// <para>
/// <b>The fail-closed property is preserved.</b> An instance that is neither in a request nor
/// assumed still answers <c>null</c>, which the context still reads as <c>Guid.Empty</c>, which
/// still matches no row. SEC-32's guarantee is unchanged; this adds a second way to be
/// <em>somebody</em>, not a way to be everybody.
/// </para>
/// <para>
/// <b>Ordering matters, and cannot be enforced by the type system.</b> The tenant is captured
/// when the <c>DbContext</c> is constructed, so <see cref="Assume"/> has to run before anything
/// in the scope resolves one. <c>ScanPipelineWorker</c> calls it as the first statement after
/// creating the scope, and a test pins that the resulting context sees the claimed job's tenant.
/// </para>
/// </remarks>
public sealed class AssumableCallerContext(IHttpContextAccessor accessor) : ICallerContext
{
    private readonly HttpCallerContext _request = new(accessor);

    private Guid? _assumedTenantId;
    private HashSet<string> _assumedScopes = [];

    /// <summary>
    /// Takes on the identity of a claimed job's tenant for the rest of this scope.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Refuses inside a request, and refuses a second time. Neither is defensive tidiness: an
    /// HTTP caller that could assume a tenant would be a privilege escalation with the tenant id
    /// supplied by the thing being escalated, and a scope that changed tenants midway would have
    /// a <c>DbContext</c> filtered to the first one and services believing the second — which
    /// reads as "the pipeline lost half its rows" rather than as a mistake anybody made here.
    /// </para>
    /// </remarks>
    /// <param name="tenantId">The tenant that owns the claimed job.</param>
    /// <exception cref="InvalidOperationException">In a request, or already assumed.</exception>
    public void Assume(Guid tenantId)
    {
        if (accessor.HttpContext is not null)
        {
            throw new InvalidOperationException(
                "A tenant cannot be assumed inside an HTTP request — the caller's own token is "
                + "the only identity a request may have.");
        }

        if (_assumedTenantId is not null)
        {
            throw new InvalidOperationException(
                $"This scope has already assumed tenant {_assumedTenantId}; a scope serves one "
                + "claimed job and therefore one tenant.");
        }

        if (tenantId == Guid.Empty)
        {
            throw new ArgumentException(
                "Guid.Empty is what an unauthenticated context resolves to, so assuming it would "
                + "match no row rather than granting access to none.", nameof(tenantId));
        }

        _assumedTenantId = tenantId;

        // The pipeline stage services take no ICallerContext of their own, so this is only ever
        // read by a scope-checking handler. It carries scan:write because that is what running a
        // scan is — see AuthScopes — and nothing broader.
        _assumedScopes = [AuthScopes.ScanWrite];
    }

    public Guid? TenantId => _assumedTenantId ?? _request.TenantId;

    /// <summary>Null when assumed: a queue-driven run was triggered by no person.</summary>
    public Guid? UserId => _assumedTenantId is null ? _request.UserId : null;

    public bool IsAuthenticated => _assumedTenantId is not null || _request.IsAuthenticated;

    public bool HasScope(string scope) =>
        _assumedTenantId is not null ? _assumedScopes.Contains(scope) : _request.HasScope(scope);

    /// <summary>Null when assumed. A worker is not a person and holds no RBAC role.</summary>
    public string? Role => _assumedTenantId is null ? _request.Role : null;
}
