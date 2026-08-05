using System.Text;

namespace SentinelAI.Infrastructure.Tests.Normalization;

/// <summary>
/// Small hand-crafted SARIF/JSON samples — deliberately not full real-tool dumps. Each carries
/// just enough shape to prove one behavior: a v1 message-as-string, a v2 rule-tag CWE, a CVE on
/// a Trivy vuln, a GHSA-only OSV advisory. Kept tiny so a failing assertion points at the field
/// it is about, not at noise.
/// </summary>
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
              "message": { "text": "Unsafe deserialization of untrusted data in OrderService." }
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
            { "ruleId": "CKV_AWS_20", "level": "error", "message": "S3 bucket allows public read access." },
            { "ruleId": "CKV_DOCKER_2", "level": "warning", "message": "Dockerfile has no HEALTHCHECK instruction." }
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
            { "ruleId": "CVE-2021-44228", "level": "error", "message": { "text": "log4j RCE in org.apache.logging.log4j." } },
            { "ruleId": "AVD-AWS-0089", "level": "warning", "message": { "text": "S3 bucket access logging is disabled." } }
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
