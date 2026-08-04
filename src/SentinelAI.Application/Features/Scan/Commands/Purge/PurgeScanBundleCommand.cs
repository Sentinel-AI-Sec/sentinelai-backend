using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Commands.Purge;

/// <summary>
/// Administratively purges a scan job's stored bundle ahead of retention (SEC-29 normally
/// does this on a schedule). Role-gated: it deletes an artifact, not just reads one.
/// </summary>
public sealed record PurgeScanBundleCommand(Guid ScanJobId) : IRequest<Response>;
