using SentinelAI.Benchmark;

namespace SentinelAI.Application.Tests.Benchmark;

/// <summary>
/// Reading a competitor's SARIF into the shape SEC-39 scores.
/// </summary>
/// <remarks>
/// <b>The failure mode this covers is silence.</b> Every mistake available here — the wrong rules
/// path, an unhandled absolute URI, a CWE spelled three ways — produces an empty or unmatched
/// result set rather than an exception, and the report then shows a competitor finding nothing
/// with perfect precision. A benchmark that flatters us because we cannot read the other tool's
/// output is worse than no benchmark.
/// </remarks>
public class SarifToolFindingsTests
{
    /// <summary>SonarQube: SARIF v2, CWE in the rule's tags, absolute build-agent path.</summary>
    private const string SonarQubeSarif = """
    {
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "SonarQube",
              "rules": [
                { "id": "csharpsquid:S2076", "properties": { "tags": ["cwe", "CWE-78", "injection"] } }
              ]
            }
          },
          "results": [
            {
              "ruleId": "csharpsquid:S2076",
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": { "uri": "file:///home/runner/work/corpus/terragoat/src/App/Shell.cs" },
                    "region": { "startLine": 88 }
                  }
                }
              ]
            }
          ]
        }
      ]
    }
    """;

    /// <summary>Snyk: CWE in properties.cwe as an array, repository-relative path.</summary>
    private const string SnykSarif = """
    {
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "Snyk Open Source",
              "rules": [
                { "id": "SNYK-DOTNET-NEWTONSOFTJSON-1", "properties": { "cwe": ["CWE-502"] } }
              ]
            }
          },
          "results": [
            {
              "ruleId": "SNYK-DOTNET-NEWTONSOFTJSON-1",
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": { "uri": "terragoat/src/App/packages.lock.json" },
                    "region": { "startLine": 12 }
                  }
                }
              ]
            }
          ]
        }
      ]
    }
    """;

    /// <summary>Checkov: SARIF v1 — rules live on the run, not on tool.driver.</summary>
    private const string CheckovSarifV1 = """
    {
      "version": "1.0.0",
      "runs": [
        {
          "tool": { "name": "Checkov" },
          "rules": [
            { "id": "CKV_AWS_290", "properties": { "tags": ["CWE-284"] } }
          ],
          "results": [
            {
              "ruleId": "CKV_AWS_290",
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": { "uri": "terragoat/infra/iam.tf" },
                    "region": { "startLine": 25 }
                  }
                }
              ]
            }
          ]
        }
      ]
    }
    """;

    /// <summary>The corpus's project names, as the runner passes them in from the labels.</summary>
    private static readonly HashSet<string> Projects =
        new(["terragoat", "kubernetes-goat", "cfngoat"], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// An absolute build-agent path is split at the project the corpus actually has.
    /// </summary>
    /// <remarks>
    /// SonarQube reports <c>/home/runner/work/corpus/terragoat/src/…</c>. Splitting at the first
    /// segment would file every one of its findings under a project called <c>home</c>, matching
    /// no label — and the report would show a competitor finding nothing, at perfect precision,
    /// because we could not read its output.
    /// </remarks>
    [Fact]
    public void An_absolute_build_agent_path_becomes_a_project_and_a_relative_file()
    {
        var finding = Assert.Single(SarifToolFindings.Read(SonarQubeSarif, "sonarqube", Projects));

        Assert.Equal("sonarqube", finding.Tool);
        Assert.Equal("terragoat", finding.Project);
        Assert.Equal("src/App/Shell.cs", finding.File);
        Assert.Equal(88, finding.Line);
        Assert.Equal("CWE-78", finding.Category);
        Assert.Equal("csharpsquid:S2076", finding.RuleId);
    }

    /// <summary>
    /// With no project names to split on, the first segment is used and the finding lands in a
    /// project the corpus does not label.
    /// </summary>
    /// <remarks>
    /// Asserted rather than left implicit because it is the degraded behaviour, and the report
    /// makes it visible: a project with no labels at all is named in the caveats, so the reader
    /// sees "we could not place these" instead of a silently wrong score.
    /// </remarks>
    [Fact]
    public void Without_the_corpus_project_names_the_split_degrades_to_the_first_segment()
    {
        var finding = Assert.Single(SarifToolFindings.Read(SonarQubeSarif, "sonarqube"));

        Assert.Equal("home", finding.Project);
    }

    /// <summary>
    /// A corpus checked out into a directory of its own name splits at the innermost one.
    /// </summary>
    /// <remarks>
    /// <c>/home/runner/work/terragoat/terragoat/infra/iam.tf</c> is what a GitHub Actions
    /// checkout of a repository called <c>terragoat</c> produces. Taking the first match would
    /// give a file path of <c>terragoat/infra/iam.tf</c>, which is one segment longer than any
    /// label — so nothing would match, and the tool would score zero recall.
    /// </remarks>
    [Fact]
    public void A_repeated_project_name_splits_at_the_innermost_one()
    {
        const string sarif = """
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "t", "rules": [ { "id": "r1", "properties": { "tags": ["CWE-284"] } } ] } },
              "results": [
                { "ruleId": "r1", "locations": [ { "physicalLocation": {
                    "artifactLocation": { "uri": "file:///home/runner/work/terragoat/terragoat/infra/iam.tf" },
                    "region": { "startLine": 25 } } } ] }
              ]
            }
          ]
        }
        """;

        var finding = Assert.Single(SarifToolFindings.Read(sarif, "t", Projects));

        Assert.Equal("terragoat", finding.Project);
        Assert.Equal("infra/iam.tf", finding.File);
    }

    /// <summary>
    /// The tool name comes from the caller, not from the SARIF driver.
    /// </summary>
    /// <remarks>
    /// Driver names vary between versions of one product — "SonarQube", "sonarqube-scanner",
    /// "SonarLint" — and a report whose columns split on that is unreadable.
    /// </remarks>
    [Fact]
    public void The_tool_name_is_the_one_the_caller_gave_not_the_sarif_driver_name()
    {
        var finding = Assert.Single(SarifToolFindings.Read(SnykSarif, "snyk", Projects));

        Assert.Equal("snyk", finding.Tool);
        Assert.Equal("CWE-502", finding.Category);
    }

    /// <summary>
    /// SARIF v1's rules live somewhere else, and Checkov still emits v1.
    /// </summary>
    /// <remarks>
    /// Reading only <c>tool.driver.rules</c> loses every category from a v1 document — findings
    /// still appear, with an empty category, so they match no label and the tool scores zero
    /// recall with no error anywhere.
    /// </remarks>
    [Fact]
    public void Version_one_sarif_rules_are_read_from_the_run_rather_than_the_driver()
    {
        var finding = Assert.Single(SarifToolFindings.Read(CheckovSarifV1, "checkov", Projects));

        Assert.Equal("CWE-284", finding.Category);
        Assert.Equal("terragoat", finding.Project);
        Assert.Equal("infra/iam.tf", finding.File);
        Assert.Equal(25, finding.Line);
    }

    /// <summary>Every spelling of a CWE normalises to one category.</summary>
    /// <remarks>
    /// Three spellings would otherwise become three columns, each scoring a third of the
    /// detections — the arithmetic still works and the answer is wrong.
    /// </remarks>
    [Theory]
    [InlineData("CWE-89")]
    [InlineData("cwe_89")]
    [InlineData("CWE 89")]
    [InlineData("external/cwe/cwe-089")]
    public void Cwe_identifiers_are_normalised_to_one_canonical_form(string spelling)
    {
        var sarif = $$"""
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "t", "rules": [ { "id": "r1", "properties": { "tags": ["{{spelling}}"] } } ] } },
              "results": [
                { "ruleId": "r1", "locations": [ { "physicalLocation": {
                    "artifactLocation": { "uri": "p/a.tf" }, "region": { "startLine": 1 } } } ] }
              ]
            }
          ]
        }
        """;

        Assert.Equal("CWE-89", Assert.Single(SarifToolFindings.Read(sarif, "t")).Category);
    }

    /// <summary>
    /// A rule carrying no CWE yields an empty category rather than a guess.
    /// </summary>
    /// <remarks>
    /// It will match no label and appear in the report as an unlabelled finding, which is the
    /// honest place for a report whose weakness class nobody stated. Inventing one would credit
    /// or blame a tool for a category it never claimed.
    /// </remarks>
    [Fact]
    public void A_rule_with_no_weakness_class_yields_an_empty_category()
    {
        const string sarif = """
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "t", "rules": [ { "id": "style-1", "properties": { "tags": ["style"] } } ] } },
              "results": [
                { "ruleId": "style-1", "locations": [ { "physicalLocation": {
                    "artifactLocation": { "uri": "p/a.tf" }, "region": { "startLine": 4 } } } ] }
              ]
            }
          ]
        }
        """;

        Assert.Equal(string.Empty, Assert.Single(SarifToolFindings.Read(sarif, "t")).Category);
    }

    /// <summary>A result with no physical location is dropped rather than placed nowhere.</summary>
    [Fact]
    public void A_result_with_no_location_is_dropped()
    {
        const string sarif = """
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "t", "rules": [ { "id": "r1", "properties": { "tags": ["CWE-284"] } } ] } },
              "results": [ { "ruleId": "r1" } ]
            }
          ]
        }
        """;

        Assert.Empty(SarifToolFindings.Read(sarif, "t"));
    }

    /// <summary>A document with no runs is empty, not an exception.</summary>
    [Fact]
    public void A_sarif_document_with_no_runs_reads_as_no_findings()
    {
        Assert.Empty(SarifToolFindings.Read("""{"version":"2.1.0"}""", "t"));
    }
}
