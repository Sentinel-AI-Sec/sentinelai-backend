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
}
