namespace SentinelAI.Domain.Abstractions;

/// <summary>
/// Thrown by an <see cref="IFindingExtractor"/> when a findings file cannot be read at all —
/// not valid JSON, or not the shape the tool is documented to emit.
/// </summary>
/// <remarks>
/// It lives in the Domain so the Application-layer pipeline can catch it and degrade
/// gracefully: one unreadable file from one scanner costs that file's findings and nothing
/// else, mirroring the runner's "one broken scanner must not fail the job" rule. A
/// <em>missing field</em> is not this exception — extractors tolerate absent fields and
/// simply yield fewer findings.
/// </remarks>
public sealed class FindingExtractionException(string message, Exception? innerException = null)
    : Exception(message, innerException);
