using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Abstractions;

// Application says WHAT it needs; Infrastructure (Microsoft Agent Framework) says HOW.
public interface IDebateEngine
{
    /// <summary>
    /// Runs the Red/Blue/Reporter debate over a scan brief and returns the adjudicated
    /// draft audit. Always terminates: the debate either converges or hits the turn-cap.
    /// </summary>
    Task<DraftAudit> RunAsync(ScanBrief brief, CancellationToken ct = default);
}
