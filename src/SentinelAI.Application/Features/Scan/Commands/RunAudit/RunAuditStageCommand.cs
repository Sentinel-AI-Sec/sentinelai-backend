using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Commands.RunAudit;

/// <summary>
/// Runs retrieve → debate → report → retention over a scan whose graph stage has already run.
/// </summary>
/// <remarks>
/// <para>
/// The sibling of <c>RunGraphStageCommand</c>, and it exists for the same declared reason: no
/// queue-driven worker exists yet, so a manually-triggered stage runner is how the pipeline is
/// exercised over HTTP. Without this the last two stages were reachable only from tests, which
/// meant a report row could never exist outside one — and an endpoint that returns reports
/// (SEC-40) would answer "not found" forever no matter how correct it was.
/// </para>
/// <para>
/// It takes the graph stage's output from the database rather than re-running it. Re-running
/// would rebuild the graph and the chains, producing a second set of rows describing the same
/// scan.
/// </para>
/// </remarks>
public sealed record RunAuditStageCommand(Guid ScanJobId) : IRequest<Response>;
