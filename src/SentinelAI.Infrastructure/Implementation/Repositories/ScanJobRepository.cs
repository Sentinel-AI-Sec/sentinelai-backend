using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Infrastructure.Implementation.Repositories;


/// <summary>Tenant-scoped scan-job queries.</summary>
/// <remarks>
/// Every query filters on <c>TenantId</c> inside the expression rather than checking after
/// the fetch. A caller asking for another tenant's job gets null, indistinguishable from a
/// job that does not exist — a 403 would confirm it does.
/// </remarks>
public class ScanJobRepository(SentinelDbContext context) : IScanJobRepository
{
    public async Task<ScanJob?> GetForTenantAsync(Guid scanJobId, Guid tenantId, CancellationToken ct = default)
        => await context.ScanJobs
            .AsNoTracking()
            .Include(j => j.Report)
            .FirstOrDefaultAsync(j => j.Id == scanJobId && j.Project!.TenantId == tenantId, ct);
 
    public async Task<Project?> GetProjectForTenantAsync(Guid projectId, Guid tenantId, CancellationToken ct = default)
        => await context.Projects
            .AsNoTracking()
            .FirstOrDefaultAsync(p => p.Id == projectId && p.TenantId == tenantId, ct);
}