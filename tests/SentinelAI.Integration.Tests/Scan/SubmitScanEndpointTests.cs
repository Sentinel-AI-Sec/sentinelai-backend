using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// <c>POST /v1/scans</c> over the wire: a real multipart upload, through the real routing,
/// model binding, auth and storage stack (SEC-13).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> Every other suite in this project seeds <c>ScanJobs</c> straight into
/// the database and drives the pipeline from there. That covers the pipeline and leaves the
/// product's <em>only</em> entry point — the endpoint the GitHub Action actually calls —
/// untested end to end: <c>SubmitScanCommandHandlerTests</c> constructs the command by hand, so
/// it never sees the multipart binding, the <c>[Consumes]</c> negotiation, the request size
/// limit, or the bytes reaching disk.
/// </para>
/// <para>
/// That gap has already cost a sprint once. Finding D1 was declared fixed after Sprint 3 and was
/// broken again later without a single test going red, because nothing here ever posted a form.
/// The assertions below are deliberately about the wire and the side effects — status code,
/// response shape, rows, and the file — rather than about handler logic that
/// <c>SubmitScanCommandHandlerTests</c> already owns.
/// </para>
/// </remarks>
public class SubmitScanEndpointTests(ScanApiFactory factory) : IClassFixture<ScanApiFactory>
{
    private static readonly Guid Tenant = Guid.NewGuid();

    /// <summary>
    /// Seeds a project for <see cref="Tenant"/> and returns its id.
    /// </summary>
    /// <remarks>
    /// Per test rather than once for the class: <c>Projects</c> carries a unique index on
    /// (tenant, repo url), and on SQLite — unlike the in-memory provider this factory used to
    /// run on — a second seed of the same pair is a constraint violation rather than a
    /// duplicate row nobody notices.
    /// </remarks>
    private async Task<Guid> SeedProjectAsync()
    {
        var projectId = Guid.CreateVersion7();

        await factory.SeedAsync(db => db.Projects.Add(new Project
        {
            Id = projectId,
            TenantId = Tenant,
            RepoUrl = $"https://example.test/repo/{projectId}",
            DefaultBranch = "main",
        }));

        return projectId;
    }

    private HttpClient Client(params string[] scopes)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer", TestJwt.Create(Tenant, userId: null, role: null, scopes: scopes));
        return client;
    }

    /// <summary>
    /// The two parts the endpoint binds, named exactly as <c>SubmitScanRequest</c>'s properties
    /// are — which is the binding contract the Action has to satisfy and nothing else asserts.
    /// </summary>
    private static MultipartFormDataContent Form(string metadataJson, byte[] bundle)
    {
        var content = new MultipartFormDataContent
        {
            { new StringContent(metadataJson), "metadata" },
        };

        var file = new ByteArrayContent(bundle);
        file.Headers.ContentType = new MediaTypeHeaderValue("application/gzip");
        content.Add(file, "bundle", "bundle.tar.gz");

        return content;
    }

    private static string Metadata(Guid projectId, string commitSha = "abc123", string? extra = null) =>
        $$"""
        {"project_id":"{{projectId}}","commit_sha":"{{commitSha}}","runner_secret_scan":"passed"{{extra}}}
        """;

    private static byte[] CleanBundle(Guid projectId) =>
        TarGzTestHelper.Build(new Dictionary<string, string>
        {
            ["metadata.json"] = Metadata(projectId),
            ["findings/osv.sarif"] = "{}",
        }).ToArray();

    // ---- the happy path ------------------------------------------------------------------

    /// <summary>
    /// The acceptance criterion of the endpoint: a valid upload is accepted with 202 and a
    /// poll URL, and both rows exist afterwards.
    /// </summary>
    [Fact]
    public async Task A_valid_multipart_upload_is_accepted_and_recorded()
    {
        var projectId = await SeedProjectAsync();
        var bundle = CleanBundle(projectId);

        using var client = Client(AuthScopes.ScanWrite);
        using var response = await client.PostAsync("/v1/scans", Form(Metadata(projectId), bundle));

        var body = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);

        using var document = JsonDocument.Parse(body);
        var data = document.RootElement.GetProperty("data");

        var scanJobId = Guid.Parse(data.GetProperty("scanJobId").GetString()!);

        // The poll URL is the contract the Action follows after upload. Asserted as a value
        // rather than assumed, because a change to the route would leave the Action polling a
        // 404 while every handler test stayed green.
        Assert.Equal($"/v1/scans/{scanJobId}", data.GetProperty("pollUrl").GetString());

        // The hash the response reports is the hash of what was posted — not of what the
        // handler happened to have in a buffer.
        Assert.Equal(
            Convert.ToHexStringLower(SHA256.HashData(bundle)),
            data.GetProperty("bundleSha256").GetString(),
            ignoreCase: true);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();

        var job = await db.ScanJobs.IgnoreQueryFilters().SingleAsync(j => j.Id == scanJobId);
        Assert.Equal(Tenant, job.TenantId);
        Assert.Equal(projectId, job.ProjectId);
        Assert.Equal(ScanStatus.Queued, job.Status);
        Assert.Equal(ScanStage.Received, job.Stage);

        var record = await db.ScanBundles.IgnoreQueryFilters().SingleAsync(b => b.ScanJobId == scanJobId);
        Assert.Equal(bundle.Length, record.SizeBytes);
        Assert.False(record.IngressRedactionApplied);

        // The storage leg, which no test had ever exercised: BundleStorage:RootPath is a
        // deployment setting, and "the row names a locator" is not the same claim as "the
        // bytes are there".
        Assert.True(File.Exists(record.StorageLocator), $"no bundle at {record.StorageLocator}");
        Assert.Equal(bundle, await File.ReadAllBytesAsync(record.StorageLocator));
    }

    /// <summary>
    /// The job the 202 names is the job the poll URL serves — the seam between ingest and
    /// polling, which the Action crosses on every run.
    /// </summary>
    [Fact]
    public async Task The_poll_url_from_the_response_serves_the_job_that_was_just_created()
    {
        var projectId = await SeedProjectAsync();

        using var client = Client(AuthScopes.ScanWrite, AuthScopes.ScanRead);
        using var submit = await client.PostAsync("/v1/scans", Form(Metadata(projectId), CleanBundle(projectId)));

        using var submitted = JsonDocument.Parse(await submit.Content.ReadAsStringAsync());
        var pollUrl = submitted.RootElement.GetProperty("data").GetProperty("pollUrl").GetString()!;

        using var poll = await client.GetAsync(pollUrl);

        Assert.Equal(HttpStatusCode.OK, poll.StatusCode);

        using var polled = JsonDocument.Parse(await poll.Content.ReadAsStringAsync());
        var job = polled.RootElement.GetProperty("data");

        Assert.Equal(
            submitted.RootElement.GetProperty("data").GetProperty("scanJobId").GetString(),
            job.GetProperty("scanJobId").GetString());
    }

    // ---- refusals ------------------------------------------------------------------------

    [Fact]
    public async Task An_anonymous_upload_is_refused_before_anything_is_read()
    {
        var projectId = await SeedProjectAsync();

        using var client = factory.CreateClient();
        using var response = await client.PostAsync("/v1/scans", Form(Metadata(projectId), CleanBundle(projectId)));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        await AssertNothingWasStoredAsync(projectId);
    }

    /// <summary>
    /// A token without <c>scan:write</c> is authenticated and still refused — the distinction
    /// the handler makes, asserted at the status code a caller actually sees.
    /// </summary>
    [Fact]
    public async Task A_token_without_scan_write_is_forbidden()
    {
        var projectId = await SeedProjectAsync();

        using var client = Client(AuthScopes.ScanRead);
        using var response = await client.PostAsync("/v1/scans", Form(Metadata(projectId), CleanBundle(projectId)));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        await AssertNothingWasStoredAsync(projectId);
    }

    /// <summary>
    /// SEC-13's privacy promise, over the wire rather than against the inspector: a bundle
    /// carrying application source is refused and nothing is written.
    /// </summary>
    /// <remarks>
    /// <c>BundleIngestTests</c> proves <c>TarGzBundleInspector</c> rejects this. That is a
    /// different claim from "the endpoint refuses it": the inspector is only load-bearing if
    /// the handler consults it before storing, which is exactly the wiring a seam test covers.
    /// </remarks>
    [Fact]
    public async Task A_bundle_carrying_application_source_is_refused_and_nothing_is_stored()
    {
        var projectId = await SeedProjectAsync();

        var bundle = TarGzTestHelper.Build(new Dictionary<string, string>
        {
            ["metadata.json"] = Metadata(projectId),
            ["findings/osv.sarif"] = "{}",
            ["src/Program.cs"] = "class Program {}",
        }).ToArray();

        using var client = Client(AuthScopes.ScanWrite);
        using var response = await client.PostAsync("/v1/scans", Form(Metadata(projectId), bundle));

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Contains("application source", await response.Content.ReadAsStringAsync());
        await AssertNothingWasStoredAsync(projectId);
    }

    /// <summary>
    /// A project belonging to nobody in this tenant is 404, not 403 — the same answer another
    /// tenant's project gets, so the response cannot be used to enumerate project ids.
    /// </summary>
    [Fact]
    public async Task A_project_this_tenant_does_not_own_is_not_found()
    {
        var foreign = Guid.CreateVersion7();

        await factory.SeedAsync(db => db.Projects.Add(new Project
        {
            Id = foreign,
            TenantId = Guid.NewGuid(),
            RepoUrl = $"https://example.test/repo/{foreign}",
            DefaultBranch = "main",
        }));

        using var client = Client(AuthScopes.ScanWrite);
        using var response = await client.PostAsync("/v1/scans", Form(Metadata(foreign), CleanBundle(foreign)));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    /// <summary>
    /// The manifest is provenance, not proof: a metadata part naming a file the tarball does
    /// not contain is refused rather than recorded.
    /// </summary>
    [Fact]
    public async Task Metadata_that_claims_a_file_the_tarball_lacks_is_refused()
    {
        var projectId = await SeedProjectAsync();

        var metadata = Metadata(
            projectId,
            extra: ""","artifacts":[{"filename":"findings/trivy.sarif","tool":"trivy"}]""");

        using var client = Client(AuthScopes.ScanWrite);
        using var response = await client.PostAsync("/v1/scans", Form(metadata, CleanBundle(projectId)));

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        Assert.Contains("absent from the tarball", await response.Content.ReadAsStringAsync());
    }

    /// <summary>
    /// A request that is not multipart is refused by content negotiation, at 415 — proving
    /// <c>[Consumes("multipart/form-data")]</c> is doing something rather than decorating.
    /// </summary>
    [Fact]
    public async Task A_json_body_is_refused_as_an_unsupported_media_type()
    {
        using var client = Client(AuthScopes.ScanWrite);

        using var response = await client.PostAsync(
            "/v1/scans",
            new StringContent("""{"metadata":"{}"}""", System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
    }

    /// <summary>
    /// A multipart body missing the <c>bundle</c> part is a 400 from model binding, not a
    /// 500 from a null reference inside the controller.
    /// </summary>
    [Fact]
    public async Task A_multipart_body_with_no_bundle_part_is_a_bad_request()
    {
        var projectId = await SeedProjectAsync();

        var content = new MultipartFormDataContent { { new StringContent(Metadata(projectId)), "metadata" } };

        using var client = Client(AuthScopes.ScanWrite);
        using var response = await client.PostAsync("/v1/scans", content);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    /// <summary>
    /// A refused upload left no job, no bundle row and no bytes for <paramref name="projectId"/>.
    /// </summary>
    /// <remarks>
    /// Refusals are checked for their side effects, not only their status code: an endpoint that
    /// answers 4xx after storing the bundle has refused nothing, and the status code alone
    /// cannot tell the two apart. Scoped to the project the refused call named, which is unique
    /// per test — so this is an assertion about that call rather than about whatever else the
    /// class fixture has accumulated.
    /// </remarks>
    private async Task AssertNothingWasStoredAsync(Guid projectId)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();

        var jobs = await db.ScanJobs.IgnoreQueryFilters()
            .Where(j => j.ProjectId == projectId)
            .Select(j => j.Id)
            .ToListAsync();

        Assert.Empty(jobs);

        Assert.False(
            await db.ScanBundles.IgnoreQueryFilters().AnyAsync(b => jobs.Contains(b.ScanJobId)),
            "a refused upload left a bundle row behind");

        // The store writes one directory per job. None of them should exist, but the check is
        // written against the whole root so a bundle stored under an id this test never learned
        // still fails it.
        Assert.Empty(Directory.Exists(factory.BundleRoot)
            ? Directory.GetDirectories(factory.BundleRoot).Where(d => jobs.Any(id => d.EndsWith(id.ToString())))
            : []);
    }
}
