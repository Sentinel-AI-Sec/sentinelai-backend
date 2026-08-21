using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Commands.Dispatch;

/// <summary>
/// Starts a scan of one branch of a registered project, without the caller supplying a bundle.
/// </summary>
/// <remarks>
/// <para>
/// Two fields, and both of them are things a person already knows. That is the whole point:
/// <c>POST /v1/scans</c> takes the GitHub Action's payload — a commit sha, a PR ref, a scanner
/// version map, and a tar.gz of scanner output — because the Action is what fills them in. Asking
/// a human to produce that by hand is asking them to be a CI runner.
/// </para>
/// <para>
/// Everything else is derived: the repository from the project, the commit from whatever the
/// branch points at when CI checks it out, the scanner versions from the scanners that run.
/// </para>
/// </remarks>
/// <param name="ProjectId">A project this tenant owns.</param>
/// <param name="GitRef">
/// The branch to scan. Optional — the project's default branch is used when it is absent, which is
/// the common case and the one that makes this a two-click operation.
/// </param>
public sealed record DispatchScanCommand(Guid ProjectId, string? GitRef = null) : IRequest<Response>;
