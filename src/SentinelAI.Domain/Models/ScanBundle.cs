namespace SentinelAI.Domain.Models
{
    public class ScanBundle
    {
        public Guid Id { get; set; }
        public Guid ScanJobId { get; set; }
        public string RunnerSecretScan { get; set; } = string.Empty;
        public bool IngressRedactionApplied { get; set; }
        public string ArtifactManifest { get; set; } = string.Empty;
        public string ScannerVersions { get; set; } = string.Empty;
        public DateTime ReceivedAt { get; set; }

        public ScanJob? ScanJob { get; set; }
    }
}
