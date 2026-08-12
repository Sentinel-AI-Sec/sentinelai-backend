using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Commands.RunGraph;

/// <summary>
/// Runs normalize + graph + chain generation over an already-ingested bundle, synchronously.
/// </summary>
/// <remarks>
/// The manual trigger for a pipeline that has no worker yet, in the same spirit as
/// <c>POST /v1/debates/demo</c>: it exists so the stages built in SEC-14 through SEC-20 can be
/// exercised end to end through the API today, without a GitHub Action run. Ingest deliberately
/// does not do this (<c>docs/Bundle_Ingest.md</c> §1: a web request cannot block on a scan), and
/// when a real queue-driven worker lands it takes this over — the pipeline this command calls is
/// the reusable part, not the command.
/// </remarks>
public sealed record RunGraphStageCommand(Guid ScanJobId) : IRequest<Response>;
