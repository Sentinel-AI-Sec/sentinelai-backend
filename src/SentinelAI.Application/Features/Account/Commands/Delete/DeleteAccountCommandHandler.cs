using System.Net;
using MediatR;
using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Account.Commands.Delete;

/// <summary>
/// Handles account deletion: authorize, then purge the caller's tenant in full (SEC-35).
/// </summary>
/// <remarks>
/// The role check is repeated here even though the controller carries
/// <c>[Authorize(Roles = "admin")]</c>, matching how every other destructive handler in this
/// codebase is written — the handler stays provably correct read on its own, without having to
/// go and confirm what attribute sits above it. For the one irreversible operation in the
/// system that is worth the duplication.
/// </remarks>
public sealed class DeleteAccountCommandHandler(
    ICallerContext caller,
    ITenantPurge purge,
    ILogger<DeleteAccountCommandHandler> logger)
    : IRequestHandler<DeleteAccountCommand, Response>
{
    public async Task<Response> Handle(DeleteAccountCommand request, CancellationToken cancellationToken)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        if (caller.Role != Roles.Admin)
            return await Response.FailureAsync(
                "deleting an account requires the admin role", HttpStatusCode.Forbidden);

        var tenantId = caller.TenantId.Value;

        // Logged before the fact and at warning level: after this returns there is no row left
        // anywhere that records the account existed, so if this line is not written first the
        // deletion leaves no trace at all.
        logger.LogWarning(
            "Account deletion requested by user {UserId} for tenant {TenantId} — this is irreversible",
            caller.UserId, tenantId);

        var report = await purge.PurgeAsync(tenantId, cancellationToken);

        return await Response.SuccessAsync(
            new DeleteAccountResponse
            {
                TenantId = tenantId,
                RowsDeleted = report.TotalRows,
                BundlesPurged = report.BundlesPurged,
                DeletedByTable = report.Rows,
            },
            "account and all associated data permanently deleted",
            HttpStatusCode.OK);
    }
}

/// <summary>Receipt for a completed account deletion.</summary>
/// <remarks>
/// It returns counts rather than a bare acknowledgement so the caller has evidence of what was
/// destroyed. This is the last response this account will ever receive; "OK" alone would leave
/// them with no record of whether anything actually happened.
/// </remarks>
public sealed record DeleteAccountResponse
{
    public required Guid TenantId { get; init; }
    public required int RowsDeleted { get; init; }
    public required int BundlesPurged { get; init; }
    public required IReadOnlyDictionary<string, int> DeletedByTable { get; init; }
}
