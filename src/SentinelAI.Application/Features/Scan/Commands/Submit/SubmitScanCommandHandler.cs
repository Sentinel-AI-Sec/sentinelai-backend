using System.Net;
using System.Text.Json;
using MediatR;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Commands.Submit;

public class SubmitScanCommandHandler(
    IUnitOfWork unitOfWork,
    IBundleInspector inspector,
    IBundleStore store,
    ICorpusVersionProvider corpus,
    ICallerContext caller)
    : IRequestHandler<SubmitScanCommand, Response>
{
    private static readonly JsonSerializerOptions MetadataJsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };
 
    private static readonly string[] AllowedTierHints = ["auto", "economy", "premium"];
 
    public async Task<Response> Handle(SubmitScanCommand request, CancellationToken cancellationToken)
    {
        // ---- 1. Authorize -------------------------------------------------------------
        if (!caller.IsAuthenticated || caller.TenantId is null)
            return await Response.FailureAsync("a machine token is required", HttpStatusCode.Unauthorized);
 
        if (!caller.HasScope(AuthScopes.ScanWrite))
            return await Response.FailureAsync(
                $"token is missing the '{AuthScopes.ScanWrite}' scope", HttpStatusCode.Forbidden);
 
        // ---- 2. Parse the metadata part -----------------------------------------------
        BundleMetadata? metadata;
        try
        {
            metadata = JsonSerializer.Deserialize<BundleMetadata>(request.MetadataJson, MetadataJsonOptions);
        }
        catch (JsonException ex)
        {
            return await Response.FailureAsync($"metadata.json is not valid JSON: {ex.Message}");
        }
 
        if (metadata is null)
            return await Response.FailureAsync("metadata.json deserialized to nothing");
 
        if (!Guid.TryParse(metadata.ProjectId, out var projectId))
            return await Response.FailureAsync(
                "metadata.project_id is missing or not a GUID - set the action's 'project-id' input");
 
        if (string.IsNullOrWhiteSpace(metadata.CommitSha))
            return await Response.FailureAsync("metadata.commit_sha is required");
 
        var tierHint = string.IsNullOrWhiteSpace(metadata.ModelTierHint)
            ? "auto"
            : metadata.ModelTierHint.ToLowerInvariant();
 
        if (!AllowedTierHints.Contains(tierHint))
            return await Response.FailureAsync(
                $"metadata.model_tier_hint must be one of: {string.Join(", ", AllowedTierHints)}");
 
        // ---- 3. Resolve the project, scoped to the caller's tenant ---------------------
        var project = await unitOfWork.ScanJobRepository
            .GetProjectForTenantAsync(projectId, caller.TenantId.Value, cancellationToken);
 
        if (project is null)
            return await Response.FailureAsync($"no project '{projectId}' for this tenant", HttpStatusCode.NotFound);
 
        // ---- 4. Vet the bundle before it is stored -------------------------------------
        var inspection = await inspector.InspectAsync(request.Bundle, cancellationToken);
        if (!inspection.IsValid)
            return await Response.FailureAsync(
                inspection.Error ?? "the bundle was rejected on ingest", HttpStatusCode.UnprocessableEntity);

        // The inspector already read request.Bundle to completion once, hashing it into its
        // own rewound copy. Storage reads from that copy rather than request.Bundle again —
        // the original may be a forward-only stream, and re-reading it would silently persist
        // a truncated or empty bundle while the DB row still claimed the correct hash/size.
        await using var rawBundle = inspection.RawBundle!;
 
        // The runner's manifest is provenance, not proof. If it claims files the tarball
        // does not contain, the two disagree and we would be recording a fiction.
        var missing = metadata.Artifacts
            .Select(a => a.Filename.Replace('\\', '/').TrimStart('.', '/'))
            .Where(f => !inspection.Entries.Contains(f, StringComparer.OrdinalIgnoreCase))
            .ToList();
 
        if (missing.Count > 0)
            return await Response.FailureAsync(
                $"metadata.artifacts lists {missing.Count} file(s) absent from the tarball: {string.Join(", ", missing.Take(5))}",
                HttpStatusCode.UnprocessableEntity);
 
        // ---- 5. Record the job ---------------------------------------------------------
        var now = DateTime.UtcNow;
 
        var job = new ScanJob
        {
            Id = Guid.CreateVersion7(),
            // From the verified token, never from the request — SEC-32.
            TenantId = caller.TenantId.Value,
            ProjectId = project.Id,
            TriggeredBy = caller.UserId,          // null for machine tokens, by design
            PrRef = metadata.PrRef,
            CommitSha = metadata.CommitSha,
            Status = ScanStatus.Queued,
            Stage = ScanStage.Received,
            ModelTierHint = tierHint,
            RetainReport = metadata.RetainReport,
            CorpusVersion = await corpus.GetCurrentVersionAsync(cancellationToken),
            BundlePurged = false,
            StartedAt = now,
        };
 
        var bundleRecord = new ScanBundle
        {
            Id = Guid.CreateVersion7(),
            TenantId = caller.TenantId.Value,
            ScanJobId = job.Id,
            RunnerSecretScan = metadata.RunnerSecretScan,
            IngressRedactionApplied = false,      // set by the redaction stage, not here
            ArtifactManifest = JsonSerializer.Serialize(metadata.Artifacts),
            ScannerVersions = metadata.ScannerVersions.ValueKind == JsonValueKind.Undefined
                ? "{}"
                : metadata.ScannerVersions.GetRawText(),
            Sha256 = inspection.Sha256,
            SizeBytes = inspection.SizeBytes,
            ReceivedAt = now,
        };
 
        // Bytes land on disk before the row is committed: a stored blob with no row is
        // reclaimable garbage, but a queued row pointing at a bundle that was never written
        // would fail in the worker, far from the cause.
        bundleRecord.StorageLocator = await store.SaveAsync(job.Id, rawBundle, cancellationToken);
 
        await unitOfWork.Repository<ScanJob>().AddAsync(job);
        await unitOfWork.Repository<ScanBundle>().AddAsync(bundleRecord);
        await unitOfWork.CompleteAsync();
 
        // ---- 6. Hand back the poll URL --------------------------------------------------
        var response = new SubmitScanResponse
        {
            ScanJobId = job.Id.ToString(),
            Status = job.Status,
            CorpusVersion = job.CorpusVersion,
            PollUrl = $"/v1/scans/{job.Id}",
            BundleSha256 = inspection.Sha256,
            CreatedAt = now,
        };
 
        return await Response.SuccessAsync(response, "scan job accepted", HttpStatusCode.Accepted);
    }
}