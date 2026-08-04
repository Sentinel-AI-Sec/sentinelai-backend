using SentinelAI.Domain.Abstractions;

namespace SentinelAI.Domain.Models
{
    public class ScanBundle : ITenantOwned
    {
        public Guid Id { get; set; }
        public Guid TenantId { get; set; }
        public Guid ScanJobId { get; set; }
        public string RunnerSecretScan { get; set; } = string.Empty;
        public bool IngressRedactionApplied { get; set; }
        public string ArtifactManifest { get; set; } = string.Empty;
        public string ScannerVersions { get; set; } = string.Empty;
        public DateTime ReceivedAt { get; set; }
        public string Sha256 { get; set; } = string.Empty;
        public long SizeBytes { get; set; }
        public string StorageLocator { get; set; } = string.Empty;

        public ScanJob? ScanJob { get; set; }
    }
}
