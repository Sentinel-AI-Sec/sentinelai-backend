using SentinelAI.Domain.Models;

namespace SentinelAI.Domain.Abstractions.Repositories;

public interface IScanJobRepository
{
    /// <summary>Job with its report, or null if it belongs to another tenant.</summary>
    Task<ScanJob?> GetForTenantAsync(Guid scanJobId, Guid tenantId, CancellationToken ct = default);
 
    /// <summary>Confirms a project is registered to this tenant before a scan is accepted.</summary>
    Task<Project?> GetProjectForTenantAsync(Guid projectId, Guid tenantId, CancellationToken ct = default);
}