using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SentinelAI.Domain.Abstractions;
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
/// <b>Every row here is keyed to a rule the committed fixture actually emits</b>, verified
/// against <c>sentinelai-fixtures/scan_out/</c>. That is not a nicety. Not one Checkov or
/// Roslyn result in that fixture carries a CWE tag of its own — all 28 Checkov infra results,
/// all 3 Docker results and all 5 Roslyn results arrive with nothing — so for the code and
/// infrastructure layers this table is the <em>only</em> path to a linking key, and a finding
/// with no linking key can never be matched to knowledge or joined into a chain.
/// </para>
/// <para>
/// The previous seed was written from the scanners' published catalogues rather than from their
/// output, and three quarters of it never fired: <c>CKV_AWS_20</c>, <c>CKV_AWS_19</c> and
/// <c>CKV_AWS_24</c> are not among the rules the fixture triggers, and the two Trivy rows were
/// keyed <c>AVD-AWS-00xx</c> where Trivy emits <c>AWS-00xx</c>. A row that never matches is
/// indistinguishable from a missing row at runtime, which is why <c>RuleMappingSeedTests</c>
/// now pins the seed against the fixture's real rule ids.
/// </para>
/// <para>
/// The ids are fixed literals, not generated: EF compares seed data by key on every
/// <c>dotnet ef migrations add</c>, so a <c>Guid.NewGuid()</c> here would produce a migration
/// that deletes and re-inserts the whole table each time.
/// </para>
/// </remarks>
public class RuleMappingConfiguration : IEntityTypeConfiguration<RuleMapping>
{
    private const string Scs = "Security Code Scan";
    private const string Ckv = "Checkov policy";
    private const string Avd = "Trivy AVD misconfiguration";

    public void Configure(EntityTypeBuilder<RuleMapping> builder)
    {
        builder.HasIndex(r => new { r.SourceTool, r.CheckId })
            .IsUnique();

        builder.HasData(Seed());
    }

    private static RuleMapping[] Seed() =>
    [
        // ---- Roslyn / Security Code Scan (code layer) ---------------------------------------
        // SCS0028 is the fixture's flagship: the unsafe-deserialization sink that carries the
        // demo's CWE-502 finding into the corpus. It reports no CWE, so this row is the link.
        Map("f099c288-0f0c-43f1-b956-f6a6233ba3eb", ScannerNames.Roslyn, "SCS0028", "CWE-502", $"{Scs}: unsafe deserialization"),
        Map("20d42173-70fa-4d33-acde-0fca5d4acb42", ScannerNames.Roslyn, "SCS0001", "CWE-78", $"{Scs}: OS command injection"),
        Map("6b1f0a4c-1d2e-4a3b-9c5d-2e7f8a9b0c11", ScannerNames.Roslyn, "SCS0002", "CWE-89", $"{Scs}: SQL injection"),
        Map("dd4f560a-16cc-462e-91d3-da21cf70de3e", ScannerNames.Roslyn, "SCS0005", "CWE-338", $"{Scs}: weak random number generator"),
        Map("7c2a1b5d-3e4f-4b6a-8d9e-1f2a3b4c5d22", ScannerNames.Roslyn, "SCS0006", "CWE-328", $"{Scs}: weak hashing function"),
        Map("8d3b2c6e-4f5a-4c7b-9e0f-2a3b4c5d6e33", ScannerNames.Roslyn, "SCS0007", "CWE-611", $"{Scs}: XML external entity (XXE)"),
        Map("7853dced-5fc7-4263-b765-8d0b2d72636e", ScannerNames.Roslyn, "SCS0018", "CWE-22", $"{Scs}: path traversal"),
        // Corrected: SCS0026 is LDAP injection (CWE-90). It was mapped to CWE-89, which is
        // SQL injection and is SCS0002 above — a wrong mapping attaches the wrong body of
        // knowledge to a real vulnerability and nothing reports an error.
        Map("b827ed21-2d56-47bd-a7c2-b9e0153d9cfc", ScannerNames.Roslyn, "SCS0026", "CWE-90", $"{Scs}: LDAP injection"),
        Map("29eea3df-8e2d-4e22-8d75-a85bfa5683d3", ScannerNames.Roslyn, "SCS0029", "CWE-79", $"{Scs}: cross-site scripting"),
        Map("9e4c3d7f-5a6b-4d8c-af10-3b4c5d6e7f44", ScannerNames.Roslyn, "SCS0004", "CWE-295", $"{Scs}: certificate validation disabled"),
        Map("af5d4e80-6b7c-4e9d-b021-4c5d6e7f8a55", ScannerNames.Roslyn, "SCS0010", "CWE-327", $"{Scs}: weak cipher algorithm"),
        Map("b06e5f91-7c8d-4fae-c132-5d6e7f8a9b66", ScannerNames.Roslyn, "SCS0012", "CWE-862", $"{Scs}: authorization bypass"),
        Map("c17f6a02-8d9e-40bf-d243-6e7f8a9b0c77", ScannerNames.Roslyn, "SCS0015", "CWE-798", $"{Scs}: hardcoded credential"),
        Map("d2807b13-9eaf-41c0-e354-7f8a9b0c1d88", ScannerNames.Roslyn, "SCS0016", "CWE-352", $"{Scs}: cross-site request forgery"),

        // ---- Checkov: IAM (infrastructure layer) --------------------------------------------
        // All four fire on the fixture's over-permissive order_task_policy — the middle hop of
        // the demo's attack chain. None of them reported a CWE before this row existed.
        Map("12f18d7c-e69e-4cde-9a0f-b12ddd332647", ScannerNames.Checkov, "CKV_AWS_288", "CWE-732", $"{Ckv}: IAM policy allows data exfiltration"),
        Map("f4a29d35-b0c1-43e2-a576-9b0c1d2e3f00", ScannerNames.Checkov, "CKV_AWS_289", "CWE-732", $"{Ckv}: IAM policy allows permissions management"),
        Map("05b3ae46-c1d2-44f3-b687-ac1d2e3f4011", ScannerNames.Checkov, "CKV_AWS_290", "CWE-732", $"{Ckv}: IAM policy allows unconstrained write"),
        Map("16c4bf57-d2e3-4504-c798-bd2e3f405122", ScannerNames.Checkov, "CKV_AWS_355", "CWE-732", $"{Ckv}: IAM policy uses \"*\" as a resource"),

        // ---- Checkov: S3 ---------------------------------------------------------------------
        Map("27d5c068-e3f4-4615-d8a9-ce3f40516233", ScannerNames.Checkov, "CKV_AWS_53", "CWE-284", $"{Ckv}: S3 block public ACLs disabled"),
        Map("38e6d179-f405-4726-e9ba-df4051627344", ScannerNames.Checkov, "CKV_AWS_54", "CWE-284", $"{Ckv}: S3 block public policy disabled"),
        Map("49f7e28a-0516-4837-facb-e05162738455", ScannerNames.Checkov, "CKV_AWS_55", "CWE-284", $"{Ckv}: S3 ignore public ACLs disabled"),
        Map("5a08f39b-1627-4948-0bdc-f16273849566", ScannerNames.Checkov, "CKV_AWS_56", "CWE-284", $"{Ckv}: S3 restrict_public_buckets disabled"),
        Map("6b1904ac-2738-4a59-1ced-027384950677", ScannerNames.Checkov, "CKV2_AWS_6", "CWE-284", $"{Ckv}: S3 bucket has no public access block"),
        Map("1b276ae3-0480-42a5-8449-a79a0ab218ab", ScannerNames.Checkov, "CKV_AWS_18", "CWE-778", $"{Ckv}: S3 access logging not enabled"),
        Map("7c2a15bd-3849-4b6a-2dfe-138495061788", ScannerNames.Checkov, "CKV_AWS_145", "CWE-311", $"{Ckv}: S3 not encrypted with KMS"),
        Map("8d3b26ce-494a-4c7b-3e0f-249506172899", ScannerNames.Checkov, "CKV_AWS_21", "CWE-693", $"{Ckv}: S3 versioning disabled"),
        Map("9e4c37df-5a5b-4d8c-4f10-35061728399a", ScannerNames.Checkov, "CKV_AWS_144", "CWE-693", $"{Ckv}: S3 cross-region replication disabled"),
        Map("af5d48e0-6b6c-4e9d-5021-4617283949ab", ScannerNames.Checkov, "CKV2_AWS_61", "CWE-693", $"{Ckv}: S3 has no lifecycle configuration"),
        Map("9299d45f-8be7-407f-8569-6cfc77d22943", ScannerNames.Checkov, "CKV2_AWS_62", "CWE-778", $"{Ckv}: S3 event notifications disabled"),

        // ---- Checkov: network, ECS, containers, secrets ---------------------------------------
        Map("dcf54bae-4eba-42f2-891a-06d3a3ed9b60", ScannerNames.Checkov, "CKV_AWS_23", "CWE-1059", $"{Ckv}: security group rule has no description"),
        Map("ea1979fc-cd3b-48c7-8dbe-16923dfc13db", ScannerNames.Checkov, "CKV_AWS_249", "CWE-250", $"{Ckv}: ECS execution and task roles are the same"),
        Map("e3918c24-afa0-42d1-9465-8a5abcdef012", ScannerNames.Checkov, "CKV_AWS_333", "CWE-1327", $"{Ckv}: ECS service assigned a public IP"),
        Map("f4a29d35-b0b1-43e2-a576-9babcdef0123", ScannerNames.Checkov, "CKV_AWS_336", "CWE-732", $"{Ckv}: ECS container root filesystem is writable"),
        Map("eef61ee4-2167-4f09-873a-8e30c5250145", ScannerNames.Checkov, "CKV_DOCKER_3", "CWE-250", $"{Ckv}: container has no non-root user"),
        Map("05b3ae46-c1c2-44f3-b687-acbcdef01234", ScannerNames.Checkov, "CKV_DOCKER_2", "CWE-693", $"{Ckv}: image has no HEALTHCHECK"),
        Map("16c4bf57-d2d3-4504-c798-bdcdef012345", ScannerNames.Checkov, "CKV_SECRET_6", "CWE-798", $"{Ckv}: hardcoded secret in the image"),

        // ---- Trivy misconfiguration (its dependency findings carry a CVE already) -------------
        // Trivy emits these WITHOUT the "AVD-" prefix its documentation uses — the fixture's
        // trivy.sarif contains AWS-0086, never AVD-AWS-0086. The prefixed rows never fired.
        Map("d62d3bff-5cea-408e-83b4-1a73c83b834d", ScannerNames.Trivy, "AWS-0086", "CWE-284", $"{Avd}: S3 public access block missing"),
        Map("27d5c068-e3e4-4615-d8a9-cedef0123456", ScannerNames.Trivy, "AWS-0087", "CWE-284", $"{Avd}: S3 block public ACLs disabled"),
        Map("1daf0baa-6a14-4f71-9dda-9841409f10ee", ScannerNames.Trivy, "AWS-0089", "CWE-778", $"{Avd}: S3 bucket access logging disabled"),
        Map("38e6d179-f4f5-4726-e9ba-dfef01234567", ScannerNames.Trivy, "AWS-0090", "CWE-693", $"{Avd}: S3 versioning disabled"),
        Map("49f7e28a-0506-4837-facb-e0f012345678", ScannerNames.Trivy, "AWS-0091", "CWE-284", $"{Avd}: S3 block public policy disabled"),
        Map("5a08f39b-1617-4948-0bdc-f10123456789", ScannerNames.Trivy, "AWS-0093", "CWE-284", $"{Avd}: S3 restrict public buckets disabled"),
        Map("6b1904ac-2728-4a59-1ced-02123456789a", ScannerNames.Trivy, "AWS-0094", "CWE-284", $"{Avd}: S3 bucket has a public ACL"),
        Map("7c2a15bd-3839-4b6a-2dfe-1323456789ab", ScannerNames.Trivy, "AWS-0104", "CWE-284", $"{Avd}: security group allows unrestricted egress"),
        Map("8d3b26ce-493a-4c7b-3e0f-2423456789bc", ScannerNames.Trivy, "AWS-0124", "CWE-1059", $"{Avd}: security group rule has no description"),
        Map("9e4c37df-5a4b-4d8c-4f10-353456789bcd", ScannerNames.Trivy, "AWS-0132", "CWE-311", $"{Avd}: S3 not encrypted with a customer-managed key"),
        Map("af5d48e0-6b5c-4e9d-5021-46456789bcde", ScannerNames.Trivy, "AWS-0345", "CWE-1327", $"{Avd}: ECS service assigned a public IP"),
        Map("b06e59f1-7c6d-4fae-6132-5756789bcdef", ScannerNames.Trivy, "DS-0002", "CWE-250", $"{Avd}: container runs as root"),
        Map("c17f6a02-8d7e-40bf-7243-68789bcdef01", ScannerNames.Trivy, "DS-0026", "CWE-693", $"{Avd}: image has no HEALTHCHECK"),
        Map("b7c1f622-1689-4892-bb30-00e6aa54bb8b", ScannerNames.Trivy, "DS-0031", "CWE-798", $"{Avd}: secret exposed in an image layer"),
    ];

    private static RuleMapping Map(string id, string sourceTool, string checkId, string cweId, string notes) =>
        new()
        {
            Id = Guid.Parse(id),
            SourceTool = sourceTool,
            CheckId = checkId,
            CweId = cweId,
            Notes = notes,
        };
}
