namespace SentinelAI.Domain.Abstractions;

/// <summary>
/// The canonical <see cref="Models.Finding.SourceTool"/> value for each scanner in the
/// toolchain. Kept in one place so the extractor that stamps a tool name and the pipeline
/// that routes a file to that extractor can never drift apart.
/// </summary>
/// <remarks>
/// Semgrep and Dependency-Check were dropped from the toolchain: Roslyn covers the code
/// layer, and OSV-Scanner replaces Dependency-Check for the dependency layer because its
/// native JSON keeps the CVE/GHSA ids a SARIF export loses.
/// </remarks>
public static class ScannerNames
{
    public const string Roslyn = "roslyn";
    public const string Osv = "osv";
    public const string Trivy = "trivy";
    public const string Checkov = "checkov";

    /// <summary>
    /// The backend's own ingress gate (SEC-33). Not a scanner the runner ships — a finding
    /// stamped with this was raised by us, on content we received, after the runner was done.
    /// </summary>
    /// <remarks>
    /// It belongs in this list because every finding has to say which tool reported it, and
    /// "the backend found this itself" is a genuinely different provenance from the four
    /// above. A reader cross-checking a finding against the bundle's <c>scanner_versions</c>
    /// will not find this one there, and should not.
    /// </remarks>
    public const string IngressGate = "ingress-gate";
}
