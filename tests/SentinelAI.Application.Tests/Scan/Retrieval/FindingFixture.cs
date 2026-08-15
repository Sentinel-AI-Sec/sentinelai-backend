using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// One unified finding per layer, carrying the messages the real scanners emit.
/// </summary>
/// <remarks>
/// The messages are sampled from <c>SentinelAI.Infrastructure.Tests.Normalization.Fixtures</c>
/// and from real tool output: OSV-Scanner's quoted coordinate with its alias clause and advisory
/// link, Roslyn's rule-id prefix and parenthesised path, Checkov's rule id followed by a
/// sentence, Trivy's stack of <c>Label: value</c> lines. That fidelity is the point — the
/// sanitizer's job is defined entirely by what these strings actually contain, and invented tidy
/// messages would pass a sanitizer that fails on the first real bundle.
/// </remarks>
internal static class FindingFixture
{
    public static readonly Guid Tenant = Guid.Parse("11111111-1111-1111-1111-111111111111");
    public static readonly Guid Job = Guid.Parse("22222222-2222-2222-2222-222222222222");

    /// <summary>OSV-Scanner on the lock file: a CVE, an alias, and an advisory URL.</summary>
    public static Finding Dependency() => new()
    {
        Id = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000001"),
        TenantId = Tenant,
        ScanJobId = Job,
        SourceTool = "osv-scanner",
        Layer = Layer.Dep,
        Severity = 4,
        CveId = "CVE-2024-21907",
        CweId = "CWE-502",
        CheckId = "CVE-2024-21907",
        Location = "Newtonsoft.Json@9.0.1",
        NodeRef = NodeId.Package("Newtonsoft.Json:9.0.1"),
        Message = "Package 'Newtonsoft.Json@9.0.1' is vulnerable to 'CVE-2024-21907' "
                + "(also known as 'GHSA-5crp-9r3c-p9vr'). See https://nvd.nist.gov/vuln/detail/CVE-2024-21907",
    };

    /// <summary>Roslyn / Security Code Scan: the CWE-502 sink the C# layer exists to find.</summary>
    public static Finding Code() => new()
    {
        Id = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000002"),
        TenantId = Tenant,
        ScanJobId = Job,
        SourceTool = "SecurityCodeScan",
        Layer = Layer.Code,
        Severity = 3,
        CweId = "CWE-502",
        CheckId = "SCS0028",
        Location = "src/OrderApp/Controllers/OrdersController.cs:16",
        NodeRef = NodeId.Code("src/OrderApp/Controllers/OrdersController.cs"),
        Message = "SCS0028: Unsafe deserialization of untrusted data in OrderService "
                + "(src/OrderApp/Controllers/OrdersController.cs:16).",
    };

    /// <summary>Checkov on the IAM policy: the wildcard and the ARN both have to survive.</summary>
    public static Finding Infra() => new()
    {
        Id = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000003"),
        TenantId = Tenant,
        ScanJobId = Job,
        SourceTool = "Checkov",
        Layer = Layer.Infra,
        Severity = 4,
        CweId = "CWE-284",
        CheckId = "CKV_AWS_290",
        Location = "infra/iam.tf:25",
        NodeRef = NodeId.Role("order-task-role"),
        Message = "CKV_AWS_290: Ensure IAM policies does not allow write access without constraint. "
                + "The aws_iam_role_policy grants s3:* on arn:aws:s3:::customer-data-bucket/*.",
    };

    /// <summary>Trivy: the stacked <c>Label: value</c> message body, plus a CVSS vector.</summary>
    public static Finding TrivyDependency() => new()
    {
        Id = Guid.Parse("aaaaaaaa-0000-0000-0000-000000000004"),
        TenantId = Tenant,
        ScanJobId = Job,
        SourceTool = "Trivy",
        Layer = Layer.Dep,
        Severity = 4,
        CveId = "CVE-2021-44228",
        CweId = "CWE-502",
        CheckId = "CVE-2021-44228",
        Location = "src/OrderApp/OrderApp.deps.json:310",
        NodeRef = NodeId.Package("Newtonsoft.Json:9.0.1"),
        Message = "Package: Newtonsoft.Json\nInstalled Version: 9.0.1\nVulnerability CVE-2021-44228\n"
                + "Severity: CRITICAL\nCVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    };

    public static IReadOnlyList<Finding> All() => [Dependency(), Code(), Infra()];
}
