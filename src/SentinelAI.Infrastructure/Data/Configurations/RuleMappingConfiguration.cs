using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data.Configurations;

/// <summary>
/// The <c>rule_mappings</c> reference table (SEC-15): tool <c>check_id</c> → CWE, resolved by
/// exact lookup for findings that arrive with no linking key.
/// </summary>
/// <remarks>
/// <para>
/// The unique index on (<c>SourceTool</c>, <c>CheckId</c>) is the invariant that makes the
/// lookup a lookup: two rows for one rule would make CWE resolution nondeterministic, so the
/// database refuses them rather than letting the pipeline pick one.
/// </para>
/// <para>
/// The seeded rows below are a starter map, not a complete catalogue — the mappings that the
/// current toolchain actually needs, each one a rule the scanner reports without a CWE of its
/// own. It grows by migration: mappings are reference data with real consequences for what
/// gets linked, so a change to them is reviewable and versioned like any other schema change.
/// OSV has no rows on purpose — its advisories already carry CVE/GHSA ids and usually a CWE,
/// so there is no gap to fill.
/// </para>
/// </remarks>
public class RuleMappingConfiguration : IEntityTypeConfiguration<RuleMapping>
{
    private const string Baseline = "Baseline exact lookup map";
    private const string ScsCatalogue = "Security Code Scan rule catalogue";
    private const string CheckovCatalogue = "Checkov policy catalogue";
    private const string TrivyCatalogue = "Trivy AVD misconfiguration catalogue";

    public void Configure(EntityTypeBuilder<RuleMapping> builder)
    {
        builder.HasIndex(r => new { r.SourceTool, r.CheckId })
            .IsUnique();

        builder.HasData(
            // ---- Roslyn / Security Code Scan (code layer) --------------------------------
            new RuleMapping
            {
                Id = Guid.Parse("f099c288-0f0c-43f1-b956-f6a6233ba3eb"),
                SourceTool = "roslyn",
                CheckId = "SCS0028",
                CweId = "CWE-502",
                Notes = Baseline
            },
            new RuleMapping
            {
                Id = Guid.Parse("20d42173-70fa-4d33-acde-0fca5d4acb42"),
                SourceTool = "roslyn",
                CheckId = "SCS0001",
                CweId = "CWE-78",
                Notes = $"{ScsCatalogue}: command injection"
            },
            new RuleMapping
            {
                Id = Guid.Parse("dd4f560a-16cc-462e-91d3-da21cf70de3e"),
                SourceTool = "roslyn",
                CheckId = "SCS0005",
                CweId = "CWE-338",
                Notes = $"{ScsCatalogue}: weak random number generator"
            },
            new RuleMapping
            {
                Id = Guid.Parse("7853dced-5fc7-4263-b765-8d0b2d72636e"),
                SourceTool = "roslyn",
                CheckId = "SCS0018",
                CweId = "CWE-22",
                Notes = $"{ScsCatalogue}: path traversal"
            },
            new RuleMapping
            {
                Id = Guid.Parse("b827ed21-2d56-47bd-a7c2-b9e0153d9cfc"),
                SourceTool = "roslyn",
                CheckId = "SCS0026",
                CweId = "CWE-89",
                Notes = $"{ScsCatalogue}: SQL injection"
            },
            new RuleMapping
            {
                Id = Guid.Parse("29eea3df-8e2d-4e22-8d75-a85bfa5683d3"),
                SourceTool = "roslyn",
                CheckId = "SCS0029",
                CweId = "CWE-79",
                Notes = $"{ScsCatalogue}: cross-site scripting"
            },

            // ---- Checkov (infrastructure layer) ------------------------------------------
            new RuleMapping
            {
                Id = Guid.Parse("b882650b-47e1-4c07-ba96-7fc3b8a13a21"),
                SourceTool = "checkov",
                CheckId = "CKV_AWS_20",
                CweId = "CWE-284",
                Notes = Baseline
            },
            new RuleMapping
            {
                Id = Guid.Parse("1b276ae3-0480-42a5-8449-a79a0ab218ab"),
                SourceTool = "checkov",
                CheckId = "CKV_AWS_18",
                CweId = "CWE-778",
                Notes = $"{CheckovCatalogue}: S3 access logging not enabled"
            },
            new RuleMapping
            {
                Id = Guid.Parse("421bbdc3-84c3-4ef7-9b24-76bb0092e491"),
                SourceTool = "checkov",
                CheckId = "CKV_AWS_19",
                CweId = "CWE-311",
                Notes = $"{CheckovCatalogue}: S3 not encrypted at rest"
            },
            new RuleMapping
            {
                Id = Guid.Parse("790afc1c-f4ea-46e8-989d-17176ab8f9a9"),
                SourceTool = "checkov",
                CheckId = "CKV_AWS_24",
                CweId = "CWE-284",
                Notes = $"{CheckovCatalogue}: security group allows ingress from 0.0.0.0/0 to port 22"
            },
            new RuleMapping
            {
                Id = Guid.Parse("eef61ee4-2167-4f09-873a-8e30c5250145"),
                SourceTool = "checkov",
                CheckId = "CKV_DOCKER_3",
                CweId = "CWE-250",
                Notes = $"{CheckovCatalogue}: container has no non-root user"
            },

            // ---- Trivy (infrastructure layer; its dep findings carry a CVE already) -------
            new RuleMapping
            {
                Id = Guid.Parse("d62d3bff-5cea-408e-83b4-1a73c83b834d"),
                SourceTool = "trivy",
                CheckId = "AVD-AWS-0086",
                CweId = "CWE-284",
                Notes = $"{TrivyCatalogue}: S3 public access block missing"
            },
            new RuleMapping
            {
                Id = Guid.Parse("1daf0baa-6a14-4f71-9dda-9841409f10ee"),
                SourceTool = "trivy",
                CheckId = "AVD-AWS-0089",
                CweId = "CWE-778",
                Notes = $"{TrivyCatalogue}: S3 bucket access logging disabled"
            }
        );
    }
}
