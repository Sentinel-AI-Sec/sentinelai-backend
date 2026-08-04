using System.Net;
using MediatR;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Queries.GetById;

public class GetScanJobQueryHandler(IUnitOfWork unitOfWork, ICallerContext caller)
    : IRequestHandler<GetScanJobQuery, Response>
{
    public async Task<Response> Handle(GetScanJobQuery request, CancellationToken cancellationToken)
    {
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a valid token is required", HttpStatusCode.Unauthorized);

        var job = await unitOfWork.ScanJobRepository
            .GetForTenantAsync(request.ScanJobId, caller.TenantId.Value, cancellationToken);

        // A job that exists but belongs to another tenant looks identical to one that does
        // not exist at all — a 403 here would confirm it does (SEC-32).
        if (job is null)
            return await Response.FailureAsync($"no scan job '{request.ScanJobId}'", HttpStatusCode.NotFound);

        return await Response.SuccessAsync(ScanJobResponse.From(job), "scan job", HttpStatusCode.OK);
    }
}
