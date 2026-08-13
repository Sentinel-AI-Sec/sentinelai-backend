using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Security;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Security;

namespace SentinelAI.Infrastructure.Tests.Security;

/// <summary>
/// SEC-33, the gate. The three acceptance criteria, plus the property the ticket calls a
/// "guaranteed backstop": it never consults the runner before deciding to run.
/// </summary>
public class IngressRedactionGateTests
{
    private static readonly Guid Tenant = Guid.CreateVersion7();
    private static readonly Guid Job = Guid.CreateVersion7();

    private static IngressRedactionGate Build(IBundleStore store) =>
        new(new RegexSecretScanner(), store, NullLogger<IngressRedactionGate>.Instance);

    private static Finding Finding(string message, string tool = "trivy") => new()
    {
        Id = Guid.CreateVersion7(),
        TenantId = Tenant,
        ScanJobId = Job,
        SourceTool = tool,
        Layer = Layer.Infra,
        Severity = 2,
        Message = message,
        Location = "infra/main.tf:10",
    };

    // ---- Criterion 1: received content is redacted before any LLM sees it -----------------

    [Fact]
    public async Task Redacts_a_secret_quoted_inside_a_finding_message()
    {
        // How a credential actually reaches a prompt: a scanner reporting something else
        // quotes the offending line, and the line happens to contain a key.
        var findings = new List<Finding>
        {
            Finding("Misconfiguration at Dockerfile:22 - ENV APP_KEY=\"kd93jfhs82hdlq09zzz1\""),
        };

        var result = await Build(new StubBundleArtifacts()).ApplyAsync("loc", findings, Tenant, Job);

        Assert.Equal(1, result.MessagesRedacted);
        Assert.DoesNotContain("kd93jfhs82hdlq09zzz1", findings[0].Message, StringComparison.Ordinal);
        Assert.Contains("[REDACTED:", findings[0].Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Sets_the_redacted_flag_only_on_the_findings_it_touched()
    {
        var dirty = Finding("token: ghp_1234567890abcdefghijklmnopqrstuvwxyz");
        var clean = Finding("S3 bucket customer-data has no encryption at rest");

        await Build(new StubBundleArtifacts()).ApplyAsync("loc", [dirty, clean], Tenant, Job);

        Assert.True(dirty.Redacted);
        Assert.False(clean.Redacted);
    }

    [Fact]
    public async Task Redacts_the_findings_the_caller_already_holds()
    {
        // The caller persists and graphs the same objects it passed in. Returning redacted
        // copies while leaving the originals dirty would write plaintext to the database with
        // redacted=true sitting beside it.
        var findings = new List<Finding> { Finding("aws_access_key_id = AKIAIOSFODNN7EXAMPLE") };

        var result = await Build(new StubBundleArtifacts()).ApplyAsync("loc", findings, Tenant, Job);

        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", findings[0].Message, StringComparison.Ordinal);
        Assert.Same(findings[0], result.Findings[0]);
    }

    // ---- Criterion 2: a hardcoded secret is reported as high severity ---------------------

    [Fact]
    public async Task Reports_a_secret_in_an_infra_artifact_as_a_high_severity_finding()
    {
        // The reference fixture's INFRA-07, verbatim: a key baked into the image via ENV.
        var store = new StubBundleArtifacts().With(
            "graph-inputs/Dockerfile",
            "FROM base\nWORKDIR /app\nENV ORDER_SVC_API_KEY=\"demo-fixture-dummy-key-not-real-000111\"\n");

        var result = await Build(store).ApplyAsync("loc", [], Tenant, Job);

        var secret = Assert.Single(result.Findings);
        Assert.Equal(IngressRedactionGate.SecretSeverity, secret.Severity);
        Assert.Equal(IngressRedactionGate.HardcodedSecretCwe, secret.CweId);
        Assert.Equal(ScannerNames.IngressGate, secret.SourceTool);
        Assert.Equal("Dockerfile:3", secret.Location);
        Assert.True(secret.Redacted);
    }

    [Fact]
    public async Task Never_quotes_the_credential_in_the_finding_it_raises()
    {
        // This finding is the thing most likely to be rendered into a prompt, a PR comment and
        // a report. Quoting the secret to explain the secret would defeat the entire gate.
        var store = new StubBundleArtifacts().With(
            "graph-inputs/infra/main.tf",
            "variable \"db_password\" {\n  type    = string\n  default = \"s3cr3tvalue123456\"\n}\n");

        var result = await Build(store).ApplyAsync("loc", [], Tenant, Job);

        Assert.DoesNotContain(
            "s3cr3tvalue123456", Assert.Single(result.Findings).Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Gives_the_secret_finding_a_canonical_node_reference()
    {
        // A finding whose node key is not one NodeId could have produced decorates nothing and
        // seeds no chain - the silent failure SEC-03 exists to prevent.
        var store = new StubBundleArtifacts().With(
            "graph-inputs/infra/iam.tf", "resource \"x\" {\n  password = \"hunter2hunter2\"\n}\n");

        var secret = Assert.Single((await Build(store).ApplyAsync("loc", [], Tenant, Job)).Findings);

        Assert.True(NodeId.IsCanonical(secret.NodeRef), $"'{secret.NodeRef}' is not canonical");
        Assert.Equal(NodeId.Resource("infra/iam.tf"), secret.NodeRef);
    }

    [Fact]
    public async Task Raises_one_finding_per_place_not_per_rule()
    {
        // A bearer JWT trips two rules on one line. Two findings would mean two things to
        // rotate, and there is one.
        var store = new StubBundleArtifacts().With(
            "graph-inputs/Dockerfile",
            "ENV AUTH=\"Bearer eyJhbGciOi.eyJzdWIiOjEyMw.SflKxwRJSMeKKF2QT4\"\n");

        Assert.Single((await Build(store).ApplyAsync("loc", [], Tenant, Job)).Findings);
    }

    // ---- Criterion 3: the flags, and the backstop property --------------------------------

    [Fact]
    public async Task Reports_what_it_did_so_the_bundle_flag_can_be_set()
    {
        var store = new StubBundleArtifacts()
            .With("graph-inputs/Dockerfile", "ENV API_KEY=\"abcdefgh12345678\"\n")
            .With("graph-inputs/infra/main.tf", "resource \"s3\" {}\n");

        var findings = new List<Finding> { Finding("password = Sup3rS3cret!") };

        var result = await Build(store).ApplyAsync("loc", findings, Tenant, Job);

        Assert.Equal(1, result.MessagesRedacted);
        Assert.Equal(1, result.ArtifactSecrets);
        Assert.Equal(2, result.ArtifactsScanned);
        Assert.True(result.FoundSecrets);
    }

    [Fact]
    public async Task Runs_regardless_of_what_the_runner_reported()
    {
        // The ticket's "independent of the runner-side Gitleaks pre-scan". The gate takes no
        // runner status as input at all - there is no parameter it could be told to trust - and
        // this pins that it still finds a secret in a bundle a runner declared clean.
        var store = new StubBundleArtifacts().With(
            "graph-inputs/Dockerfile", "ENV APP_SECRET=\"leaked-value-99887766\"\n");

        Assert.Equal(1, (await Build(store).ApplyAsync("loc", [], Tenant, Job)).ArtifactSecrets);
    }

    // ---- Degradation ----------------------------------------------------------------------

    [Fact]
    public async Task Still_redacts_the_findings_when_the_bundle_cannot_be_read()
    {
        // An unreadable bundle fails loudly in the graph stage, which is where that diagnosis
        // belongs. A redaction step that turned a degraded scan into no scan would get switched
        // off, and then there would be no redaction at all.
        var findings = new List<Finding> { Finding("api_key = abcdefgh12345678") };

        var result = await Build(new StubBundleArtifacts(throwOnRead: true))
            .ApplyAsync("loc", findings, Tenant, Job);

        Assert.Equal(1, result.MessagesRedacted);
        Assert.Equal(0, result.ArtifactsScanned);
    }

    [Fact]
    public async Task Leaves_a_clean_bundle_completely_alone()
    {
        var store = new StubBundleArtifacts().With(
            "graph-inputs/infra/main.tf",
            "resource \"aws_s3_bucket\" \"data\" {\n  bucket = \"customer-data\"\n}\n");

        var findings = new List<Finding> { Finding("S3 bucket has no encryption at rest") };
        var before = findings[0].Message;

        var result = await Build(store).ApplyAsync("loc", findings, Tenant, Job);

        Assert.False(result.FoundSecrets);
        Assert.Equal(before, findings[0].Message);
        Assert.False(findings[0].Redacted);
        Assert.Single(result.Findings);
    }

    [Fact]
    public async Task Keeps_going_when_an_artifact_is_not_text()
    {
        // Bundles carry whatever the runner collected. One undecodable file must not stop the
        // gate reading the rest.
        var store = new StubBundleArtifacts()
            .WithBytes("graph-inputs/blob.bin", [0xFF, 0xFE, 0x00, 0x01, 0x02])
            .With("graph-inputs/Dockerfile", "ENV API_KEY=\"abcdefgh12345678\"\n");

        var result = await Build(store).ApplyAsync("loc", [], Tenant, Job);

        Assert.Equal(1, result.ArtifactSecrets);
        Assert.Equal(2, result.ArtifactsScanned);
    }
}
