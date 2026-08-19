using System.Text;

namespace SentinelAI.Infrastructure.Tests.Normalization;

/// <summary>
/// Small hand-crafted SARIF/JSON samples — deliberately not full real-tool dumps. Each carries
/// just enough shape to prove one behavior: a v1 message-as-string, a v2 rule-tag CWE, a CVE on
/// a Trivy vuln, a GHSA-only OSV advisory. Kept tiny so a failing assertion points at the field
/// it is about, not at noise.
/// </summary>
/// <remarks>
/// The locations mirror the shapes the committed fixture's real scanners emit, because the
/// differences are load-bearing: Roslyn reports the build agent's absolute author path,
/// Checkov and Trivy report repo-relative ones, and Trivy names the vulnerable package only in
/// the message body. Sample them wrong and the normalization looks correct here while
/// producing machine-dependent dedup keys and node references on real output.
/// </remarks>
internal static class Fixtures
{
    public static Stream ToStream(string content) => new MemoryStream(Encoding.UTF8.GetBytes(content));

    public const string InvalidJson = "{ this is not valid json";

    // Roslyn / Security Code Scan — SARIF v2, message as an object, CWE on the rule's tags.
    public const string RoslynSarifV2 = """
    {
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "SecurityCodeScan",
              "rules": [
                { "id": "SCS0028", "properties": { "tags": ["security", "CWE-502"] } }
              ]
            }
          },
          "results": [
            {
              "ruleId": "SCS0028",
              "level": "warning",
              "message": { "text": "Unsafe deserialization of untrusted data in OrderService." },
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": { "uri": "file:///C:/Users/PC_STORE/Downloads/sentinelai-fixture_2/sentinelai-fixture/src/OrderApp/Controllers/OrdersController.cs" },
                    "region": { "startLine": 16, "startColumn": 28 }
                  }
                }
              ]
            }
          ]
        }
      ]
    }
    """;

    // Checkov — SARIF v1: message is a bare string, rules under run.rules, level on the result.
    public const string CheckovSarifV1 = """
    {
      "version": "1.0.0",
      "runs": [
        {
          "tool": { "name": "Checkov" },
          "rules": [
            { "id": "CKV_AWS_20", "properties": { "tags": ["CWE-284"] } }
          ],
          "results": [
            {
              "ruleId": "CKV_AWS_20", "level": "error", "message": "S3 bucket allows public read access.",
              "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "infra/main.tf" }, "region": { "startLine": 41 } } }]
            },
            {
              "ruleId": "CKV_DOCKER_2", "level": "warning", "message": "Dockerfile has no HEALTHCHECK instruction.",
              "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "Dockerfile" }, "region": { "startLine": 1 } } }]
            }
          ]
        }
      ]
    }
    """;

    // Trivy — SARIF v2 mixing a dependency vulnerability (CVE) and an infra misconfiguration.
    public const string TrivySarifV2 = """
    {
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "Trivy",
              "rules": [
                { "id": "CVE-2021-44228", "properties": { "tags": ["CWE-502"], "security-severity": "10.0" } },
                { "id": "AVD-AWS-0089", "properties": { "tags": ["misconfiguration"] } }
              ]
            }
          },
          "results": [
            {
              "ruleId": "CVE-2021-44228", "level": "error",
              "message": { "text": "Package: Newtonsoft.Json\nInstalled Version: 9.0.1\nVulnerability CVE-2021-44228\nSeverity: CRITICAL" },
              "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "src/OrderApp/OrderApp.deps.json" }, "region": { "startLine": 310 } } }]
            },
            {
              "ruleId": "AVD-AWS-0089", "level": "warning",
              "message": { "text": "S3 bucket access logging is disabled." },
              "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "infra/main.tf" }, "region": { "startLine": 12 } } }]
            }
          ]
        }
      ]
    }
    """;

    // Checkov against the Dockerfile — SARIF v2, one result, so the two Checkov files in a
    // bundle contribute a distinct number of findings rather than the same sample twice.
    public const string CheckovDockerSarifV2 = """
    {
      "version": "2.1.0",
      "runs": [
        {
          "tool": { "driver": { "name": "Checkov", "rules": [] } },
          "results": [
            {
              "ruleId": "CKV_DOCKER_3", "level": "warning",
              "message": { "text": "Image runs as root." },
              "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "Dockerfile" }, "region": { "startLine": 3 } } }]
            }
          ]
        }
      ]
    }
    """;

    // OSV-Scanner — SARIF. This is the shape the runner actually writes (scripts/run-scanners.sh
    // emits --format sarif), and the shape the pipeline used to route out entirely. Two things
    // it carries that the "SARIF drops the linking ids" warning claimed it would not: the CVE
    // is the ruleId, and the package coordinate is stated in the message.
    public const string OsvSarifV2 = """
    {
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "osv-scanner",
              "rules": [
                { "id": "CVE-2024-21907", "shortDescription": { "text": "CVE-2024-21907: Improper handling in Newtonsoft.Json" } },
                { "id": "GHSA-2cmq-823j-5qj8", "shortDescription": { "text": "Out-of-bounds write in SixLabors ImageSharp" } }
              ]
            }
          },
          "results": [
            {
              "ruleId": "CVE-2024-21907",
              "level": "warning",
              "message": { "text": "Package 'Newtonsoft.Json@9.0.1' is vulnerable to 'CVE-2024-21907' (also known as 'GHSA-5crp-9r3c-p9vr')." },
              "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "file:///home/runner/work/repo/repo/src/OrderApp/packages.lock.json" } } }]
            },
            {
              "ruleId": "GHSA-2cmq-823j-5qj8",
              "level": "error",
              "message": { "text": "Package 'SixLabors.ImageSharp@1.0.4' is vulnerable to 'GHSA-2cmq-823j-5qj8'." },
              "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "file:///home/runner/work/repo/repo/src/OrderApp/packages.lock.json" } } }]
            }
          ]
        }
      ]
    }
    """;

    // OSV-Scanner — native JSON. First vuln resolves a CVE from its aliases; second is GHSA-only.
    public const string OsvNativeJson = """
    {
      "results": [
        {
          "source": { "path": "packages.lock.json", "type": "lockfile" },
          "packages": [
            {
              "package": { "name": "Newtonsoft.Json", "version": "9.0.1", "ecosystem": "NuGet" },
              "vulnerabilities": [
                {
                  "id": "GHSA-5crp-9r3c-p9vr",
                  "aliases": ["CVE-2024-21907"],
                  "summary": "Improper handling of exceptional conditions in Newtonsoft.Json.",
                  "severity": [{ "type": "CVSS_V3", "score": "7.5" }],
                  "database_specific": { "severity": "HIGH", "cwe_ids": ["CWE-755"] }
                },
                {
                  "id": "GHSA-aaaa-bbbb-cccc",
                  "aliases": [],
                  "summary": "A GHSA-only advisory carrying no CVE alias.",
                  "database_specific": { "severity": "MODERATE" }
                }
              ]
            }
          ]
        }
      ]
    }
    """;
}
