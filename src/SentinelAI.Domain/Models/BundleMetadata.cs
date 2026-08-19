using System.Text.Json;
using System.Text.Json.Serialization;

namespace SentinelAI.Domain.Models;


/// <summary>
/// The <c>metadata.json</c> part of the multipart upload, exactly as
/// <c>scripts/build-metadata.sh</c> writes it in sentinelai-action.
/// </summary>
/// <remarks>
/// Field names are snake_case on the wire. <c>project_id</c> may be an empty
/// string when the caller did not set the input — that is a 400, not a crash.
/// </remarks>
public sealed class BundleMetadata
{
    [JsonPropertyName("project_id")] public string ProjectId { get; init; } = string.Empty;
    [JsonPropertyName("pr_ref")] public string PrRef { get; init; } = string.Empty;
    [JsonPropertyName("commit_sha")] public string CommitSha { get; init; } = string.Empty;
    [JsonPropertyName("model_tier_hint")] public string ModelTierHint { get; init; } = "auto";
    [JsonPropertyName("retain_report")] public bool RetainReport { get; init; }
    [JsonPropertyName("runner_secret_scan")] public string RunnerSecretScan { get; init; } = "skipped";
 
    /// <summary>Raw scanner-version block; stored verbatim as provenance.</summary>
    [JsonPropertyName("scanner_versions")] public JsonElement ScannerVersions { get; init; }
 
    [JsonPropertyName("artifacts")] public List<BundleArtifact> Artifacts { get; init; } = [];
}
 
/// <summary>One entry of the manifest the runner generated from what is actually in the bundle.</summary>
public sealed class BundleArtifact
{
    /// <summary>sarif | dot | tf | dockerfile | manifest | provenance | other</summary>
    [JsonPropertyName("kind")] public string Kind { get; init; } = string.Empty;
 
    /// <summary>checkov | trivy | osv-scanner | roslyn-security | terraform | docker | nuget | npm | sentinelai</summary>
    [JsonPropertyName("tool")] public string Tool { get; init; } = string.Empty;
 
    /// <summary>Path relative to the bundle root, e.g. <c>findings/osv.sarif</c>.</summary>
    [JsonPropertyName("filename")] public string Filename { get; init; } = string.Empty;
}