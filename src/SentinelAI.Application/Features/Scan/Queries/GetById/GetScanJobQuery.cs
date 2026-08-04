using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Queries.GetById;

/// <summary>Polls a scan job — the poll URL SEC-13's 202 response hands back.</summary>
public sealed record GetScanJobQuery(Guid ScanJobId) : IRequest<Response>;
