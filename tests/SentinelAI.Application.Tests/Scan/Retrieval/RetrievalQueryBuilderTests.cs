using SentinelAI.Application.Features.Scan.Retrieval;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;

namespace SentinelAI.Application.Tests.Scan.Retrieval;

/// <summary>
/// SEC-21's first acceptance box: a finding becomes a query carrying its identifiers and a
/// concise description, with none of the scanner's own boilerplate.
/// </summary>
/// <remarks>
/// <para>
/// The messages below are copied from the committed fixture's real scanner output
/// (<c>sentinelai-fixtures/scan_out/</c>), not paraphrased. Boilerplate is a property of what
/// these four tools actually emit, so a test written against invented messages would pass for a
/// builder that strips nothing — the Trivy case in particular is six lines of fields and one
/// markdown link, and it is the reason this class exists.
/// </para>
/// <para>
/// Assertions are on what must and must not appear rather than on the whole string. Pinning the
/// exact query would make every wording change a test change and would say nothing about why the
/// wording matters; what matters is that the identifier leads, the subject is named, and the
/// scanner's scaffolding is gone.
/// </para>
/// </remarks>
public class RetrievalQueryBuilderTests
{
    private static readonly RetrievalQueryBuilder Builder = new();

    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private static Finding Finding(
        Layer layer, string nodeRef, string message,
        string? cwe = null, string? cve = null, string tool = "test", string? checkId = null) => new()
        {
            Id = Guid.CreateVersion7(),
            TenantId = Tenant,
            ScanJobId = Job,
            SourceTool = tool,
            CheckId = checkId,
            Layer = layer,
            Severity = 4,
            CweId = cwe,
            CveId = cve,
            NodeRef = nodeRef,
            Message = message,
        };

    // ---- The identifier leads, and the subject is named -------------------------------------

    [Fact]
    public void A_code_finding_becomes_its_cwe_its_component_and_what_the_scanner_said()
    {
        var finding = Finding(
            Layer.Code,
            NodeId.Code("src/OrderApp/Controllers/OrdersController.cs"),
            "TypeNameHandling is set to the other value than 'None'. It may lead to deserialization vulnerability.",
            cwe: "CWE-502", tool: "roslyn", checkId: "SCS0028");

        var query = Builder.Build(finding)!;

        // The exact-match key first: SEC-10 keeps id lookup as its own retrieval path.
        Assert.StartsWith("CWE-502", query, StringComparison.Ordinal);

        // The component, without the directories or the extension the corpus knows nothing about.
        Assert.Contains("orderscontroller", query, StringComparison.Ordinal);
        Assert.DoesNotContain("src/", query, StringComparison.Ordinal);
        Assert.DoesNotContain(".cs", query, StringComparison.OrdinalIgnoreCase);

        // The description survives — this is a finding whose message genuinely says something.
        Assert.Contains("TypeNameHandling", query, StringComparison.Ordinal);
        Assert.Contains("deserialization", query, StringComparison.Ordinal);

        // And nothing that identifies the scanner rather than the weakness.
        Assert.DoesNotContain("roslyn", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("SCS0028", query, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Both_identifiers_travel_when_a_finding_carries_both()
    {
        var finding = Finding(
            Layer.Dep, NodeId.Package("newtonsoft.json:12.0.1"),
            "Deserialization of untrusted data.", cwe: "CWE-502", cve: "CVE-2024-21907");

        var query = Builder.Build(finding)!;

        // CWE first: it names the weakness class the offensive corpus is organised by, and the
        // CVE is the narrower key for one instance of it. Both retrieve different chunks.
        Assert.StartsWith("CWE-502 CVE-2024-21907", query, StringComparison.Ordinal);
    }

    [Fact]
    public void A_finding_with_no_cwe_and_no_cve_gets_no_query_at_all()
    {
        // Nothing the corpus can be keyed on. A prose-only query would still retrieve something,
        // and that something would be a plausible answer to a question nobody asked.
        var finding = Finding(Layer.Code, NodeId.Code("orderservice"), "Weak hashing function.");

        Assert.Null(Builder.Build(finding));
    }

    // ---- No scanner boilerplate ------------------------------------------------------------

    /// <summary>
    /// Trivy's real message shape, and the case the old <c>"{key} {message}"</c> query handled
    /// worst: every dependency finding in a scan shared the words "installed version", "fixed
    /// version" and a severity word, so the embeddings of all of them pointed at the same place.
    /// </summary>
    [Fact]
    public void A_trivy_dependency_message_contributes_none_of_its_fields()
    {
        var finding = Finding(
            Layer.Dep, NodeId.Package("microsoft.data.sqlclient:2.1.1"),
            "Package: Microsoft.Data.SqlClient\nInstalled Version: 2.1.1\n"
            + "Vulnerability CVE-2024-0056\nSeverity: HIGH\nFixed Version: 2.1.7, 3.1.5, 4.0.5, 5.1.3\n"
            + "Link: [CVE-2024-0056](https://avd.aquasec.com/nvd/cve-2024-0056)",
            cve: "CVE-2024-0056", tool: "trivy");

        var query = Builder.Build(finding)!;

        Assert.StartsWith("CVE-2024-0056", query, StringComparison.Ordinal);
        Assert.Contains("microsoft.data.sqlclient 2.1.1", query, StringComparison.Ordinal);

        Assert.DoesNotContain("Installed Version", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Fixed Version", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Severity", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("HIGH", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("http", query, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("aquasec", query, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// OSV's message is a sentence, but it says only what the identifiers and the package
    /// coordinate already say — plus two alias spellings of the same advisory.
    /// </summary>
    [Fact]
    public void An_osv_message_that_only_restates_the_identifiers_adds_nothing_to_the_query()
    {
        var finding = Finding(
            Layer.Dep, NodeId.Package("sixlabors.imagesharp:1.0.4"),
            "Package 'SixLabors.ImageSharp@1.0.4' is vulnerable to 'CVE-2025-27598' "
            + "(also known as 'GHSA-2cmq-823j-5qj8').",
            cve: "CVE-2025-27598", tool: "osv-scanner");

        var query = Builder.Build(finding)!;

        Assert.Equal("CVE-2025-27598 vulnerable dependency sixlabors.imagesharp 1.0.4", query);

        // The alias in particular: a query carrying three spellings of one advisory retrieves the
        // alias list rather than anything about the weakness.
        Assert.DoesNotContain("GHSA", query, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_redaction_marker_never_reaches_the_corpus()
    {
        // The marker is proof the SEC-33 gate ran, not something to search for, and every
        // redacted finding in the scan would otherwise share the identical token.
        var finding = Finding(
            Layer.Infra, NodeId.For(NodeType.Resource, "infra/main.tf"),
            "Hardcoded credential [REDACTED:aws-access-key] in the task definition environment.",
            cwe: "CWE-798");

        var query = Builder.Build(finding)!;

        Assert.DoesNotContain("REDACTED", query, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Hardcoded credential", query, StringComparison.Ordinal);
    }

    // ---- Per-layer templates ----------------------------------------------------------------

    [Fact]
    public void Each_layer_names_its_subject_in_its_own_words()
    {
        var dep = Builder.Build(Finding(
            Layer.Dep, NodeId.Package("newtonsoft.json:12.0.1"), "Deserialization of untrusted data.",
            cve: "CVE-2024-21907"))!;

        var code = Builder.Build(Finding(
            Layer.Code, NodeId.Code("orderservice"), "Weak hashing function.", cwe: "CWE-328"))!;

        var infra = Builder.Build(Finding(
            Layer.Infra, NodeId.Role("order_task_role"),
            "Ensure IAM policies does not allow data exfiltration", cwe: "CWE-732"))!;

        Assert.Contains("vulnerable dependency newtonsoft.json 12.0.1", dep, StringComparison.Ordinal);
        Assert.Contains("vulnerable code in orderservice", code, StringComparison.Ordinal);

        // The infra template names the kind of resource, because a finding on a role and a finding
        // on a bucket want different chunks even under one CWE.
        Assert.Contains("insecure iam role order_task_role", infra, StringComparison.Ordinal);
    }

    [Fact]
    public void A_package_whose_name_ends_like_a_filename_keeps_all_of_it()
    {
        // The single most damaging thing a "strip the extension" rule could do: pkg:newtonsoft.json
        // is the fixture's flagship dependency, and "newtonsoft" retrieves nothing about it.
        var finding = Finding(
            Layer.Dep, NodeId.Package("newtonsoft.json"), "Deserialization of untrusted data.",
            cve: "CVE-2024-21907");

        Assert.Contains("newtonsoft.json", Builder.Build(finding)!, StringComparison.Ordinal);
    }

    [Fact]
    public void A_finding_whose_node_reference_names_no_subject_still_produces_a_query()
    {
        // Being loud about an unjoinable reference is GraphSeeder's job, not this one's. Here the
        // template simply loses its subject rather than the finding losing its retrieval.
        var finding = Finding(Layer.Code, "orderservice", "Weak hashing function.", cwe: "CWE-328");

        var query = Builder.Build(finding)!;

        Assert.StartsWith("CWE-328 vulnerable code", query, StringComparison.Ordinal);
        Assert.Contains("hashing", query, StringComparison.Ordinal);
    }

    [Fact]
    public void A_long_message_is_cut_to_a_search_phrase()
    {
        var finding = Finding(
            Layer.Code, NodeId.Code("orderservice"),
            string.Join(' ', Enumerable.Range(1, 60).Select(i => $"word{i}")), cwe: "CWE-502");

        var query = Builder.Build(finding)!;

        Assert.Contains("word1 ", query, StringComparison.Ordinal);
        Assert.DoesNotContain($"word{RetrievalQueryBuilder.MaxDescriptionWords + 1}", query, StringComparison.Ordinal);
    }
}
