using System.Net;
using MediatR;
using SentinelAI.Application.Features.Scan.Queries.GetById;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Commands.Purge;

public class PurgeScanBundleCommandHandler(IUnitOfWork unitOfWork, IBundleStore store, ICallerContext caller)
    : IRequestHandler<PurgeScanBundleCommand, Response>
{
    public async Task<Response> Handle(PurgeScanBundleCommand request, CancellationToken cancellationToken)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        // [Authorize(Roles = "admin")] already gates this at the controller; checked again
        // here so the handler is provably correct on its own, the same way the scan-write
        // scope is re-checked in SubmitScanCommandHandler rather than trusted to the pipe.
        if (caller.Role != Roles.Admin)
            return await Response.FailureAsync("this action requires the admin role", HttpStatusCode.Forbidden);

        var job = await unitOfWork.ScanJobRepository
            .GetForTenantAsync(request.ScanJobId, caller.TenantId.Value, cancellationToken);

        if (job is null)
            return await Response.FailureAsync($"no scan job '{request.ScanJobId}'", HttpStatusCode.NotFound);

        if (!job.BundlePurged)
        {
            await store.PurgeAsync(job.Id, cancellationToken);
            job.BundlePurged = true;

            await unitOfWork.Repository<ScanJob>().UpdateAsync(job);
            await unitOfWork.CompleteAsync();
        }

        return await Response.SuccessAsync(ScanJobResponse.From(job), "bundle purged", HttpStatusCode.OK);
    }
}
