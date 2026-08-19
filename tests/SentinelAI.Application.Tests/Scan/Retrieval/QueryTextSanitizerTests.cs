using SentinelAI.Application.Features.Scan.Retrieval;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// Pins the sanitizer's two halves: what it must remove, and — more importantly — what it must
/// never remove.
/// </summary>
public sealed class QueryTextSanitizerTests
{
    // ---- the two named traps ------------------------------------------------------------
    //
    // PIPELINE_A_CONTEXT.md §6.1: "a naive path-stripper eats Newtonsoft.Json; a naive markdown
    // cleaner eats s3:*. Whatever stripping SEC-21 applies, pin both with regression tests."
    // These two tests are that pin. They are not examples — they are the requirement.

    [Theory]
    [InlineData("Package 'Newtonsoft.Json@9.0.1' is vulnerable.", "Newtonsoft.Json")]
    [InlineData("System.Text.Json mishandles untrusted input.", "System.Text.Json")]
    [InlineData("SixLabors.ImageSharp writes out of bounds.", "SixLabors.ImageSharp")]
    [InlineData("A flaw in Microsoft.Data.SqlClient.dll handling.", "Microsoft.Data.SqlClient")]
    public void Keeps_package_names_that_look_like_file_paths(string message, string packageName)
    {
        Assert.Contains(packageName, QueryTextSanitizer.Clean(message), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("The role policy grants s3:* on the bucket.", "s3:*")]
    [InlineData("Resource is set to \"*\" for all actions.", "*")]
    [InlineData("Allows s3:GetObject and s3:PutObject.", "s3:GetObject")]
    [InlineData("IAM policy uses a wildcard action *:* across accounts.", "*:*")]
    public void Keeps_wildcards_that_a_markdown_cleaner_would_eat(string message, string wildcard)
    {
        Assert.Contains(wildcard, QueryTextSanitizer.Clean(message), StringComparison.Ordinal);
    }

    [Fact]
    public void Keeps_an_arn_intact_even_though_it_contains_a_slash()
    {
        var cleaned = QueryTextSanitizer.Clean(
            "The policy grants s3:* on arn:aws:s3:::customer-data-bucket/*.");

        Assert.Contains("arn:aws:s3:::customer-data-bucket/*", cleaned, StringComparison.Ordinal);
    }

    // ---- what must go ------------------------------------------------------------------

    [Fact]
    public void Removes_file_paths_and_line_numbers()
    {
        var cleaned = QueryTextSanitizer.Clean(
            "Unsafe deserialization in src/OrderApp/Controllers/OrdersController.cs:16.");

        Assert.DoesNotContain("OrdersController", cleaned, StringComparison.Ordinal);
        Assert.DoesNotContain(":16", cleaned, StringComparison.Ordinal);
        Assert.Contains("Unsafe deserialization", cleaned, StringComparison.Ordinal);
    }

    [Fact]
    public void Removes_an_absolute_build_agent_path()
    {
        var cleaned = QueryTextSanitizer.Clean(
            "Issue at file:///C:/Users/PC_STORE/Downloads/fixture/src/OrderApp/Program.cs — unsafe call.");

        Assert.DoesNotContain("PC_STORE", cleaned, StringComparison.Ordinal);
        Assert.DoesNotContain("Program.cs", cleaned, StringComparison.Ordinal);
        Assert.Contains("unsafe call", cleaned, StringComparison.Ordinal);
    }

    [Fact]
    public void Removes_cvss_vectors_urls_and_tool_rule_ids()
    {
        var cleaned = QueryTextSanitizer.Clean(
            "CKV_AWS_290: S3 bucket allows public read access. "
            + "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H "
            + "See https://docs.example.com/rules/CKV_AWS_290 for details.");

        Assert.DoesNotContain("CKV_AWS_290", cleaned, StringComparison.Ordinal);
        Assert.DoesNotContain("CVSS", cleaned, StringComparison.Ordinal);
        Assert.DoesNotContain("http", cleaned, StringComparison.Ordinal);
        Assert.Contains("S3 bucket allows public read access", cleaned, StringComparison.Ordinal);
    }

    [Fact]
    public void Drops_the_label_lines_of_a_stacked_trivy_message()
    {
        var cleaned = QueryTextSanitizer.Clean(FindingFixture.TrivyDependency().Message);

        Assert.DoesNotContain("Installed Version", cleaned, StringComparison.Ordinal);
        Assert.DoesNotContain("Severity", cleaned, StringComparison.Ordinal);
        Assert.DoesNotContain("CVSS", cleaned, StringComparison.Ordinal);
        Assert.Contains("CVE-2021-44228", cleaned, StringComparison.Ordinal);
    }

    [Fact]
    public void Drops_the_alias_clause_whole_rather_than_leaving_an_empty_parenthesis()
    {
        var cleaned = QueryTextSanitizer.Clean(FindingFixture.Dependency().Message);

        Assert.DoesNotContain("also known as", cleaned, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("GHSA", cleaned, StringComparison.Ordinal);
        Assert.DoesNotContain("()", cleaned, StringComparison.Ordinal);
        Assert.DoesNotContain("''", cleaned, StringComparison.Ordinal);
    }

    [Fact]
    public void Takes_a_see_link_out_as_a_unit_and_leaves_no_dangling_verb()
    {
        var cleaned = QueryTextSanitizer.Clean(
            "Improper handling of exceptional conditions. See https://nvd.nist.gov/vuln/detail/CVE-2024-21907");

        Assert.Equal("Improper handling of exceptional conditions.", cleaned);
    }

    [Fact]
    public void Keeps_cve_and_cwe_identifiers()
    {
        var cleaned = QueryTextSanitizer.Clean(
            "CVE-2024-21907 in Newtonsoft.Json is an instance of CWE-502.");

        Assert.Contains("CVE-2024-21907", cleaned, StringComparison.Ordinal);
        Assert.Contains("CWE-502", cleaned, StringComparison.Ordinal);
    }

    [Fact]
    public void Flattens_a_multi_line_message_to_one_line()
    {
        var cleaned = QueryTextSanitizer.Clean("First line.\nSecond line.\r\nThird line.");

        Assert.DoesNotContain("\n", cleaned, StringComparison.Ordinal);
        Assert.DoesNotContain("\r", cleaned, StringComparison.Ordinal);
        Assert.Equal("First line. Second line. Third line.", cleaned);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Degrades_to_empty_rather_than_throwing(string? message)
    {
        Assert.Equal(string.Empty, QueryTextSanitizer.Clean(message));
    }
}
