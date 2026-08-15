using System.Net;
using System.Text.Json;
using SentinelAI.Application.Common.Paging;
using SentinelAI.Domain.Models;
using SentinelAI.Integration.Tests.Auth;

namespace SentinelAI.Integration.Tests.ReadApi;

/// <summary>
/// Cursor pagination and RFC 7807 errors (SEC-40).
/// </summary>
/// <remarks>
/// The seeded scan has three findings, so a limit of one walks three pages and proves the
/// cursor actually advances — a paging implementation that ignores the cursor returns page one
/// forever and looks perfectly healthy until somebody scrolls.
/// </remarks>
public class ReadApiPagingTests : IClassFixture<ScanApiFactory>
{
    private readonly ReadApiFixture _fixture;

    public ReadApiPagingTests(ScanApiFactory factory)
    {
        _fixture = new ReadApiFixture(factory);
        _fixture.SeedAsync().GetAwaiter().GetResult();
    }

    private HttpClient Reader() => _fixture.Client(AuthScopes.ScanRead, AuthScopes.ReportRead);

    [Fact]
    public async Task Walking_the_cursor_returns_every_finding_exactly_once()
    {
        var client = Reader();
        var seen = new List<string>();
        string? cursor = null;

        for (var page = 0; page < 10; page++)
        {
            var url = $"/v1/scans/{_fixture.ScanJobId}/findings?limit=1"
                      + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}");

            var json = await ReadApiFixture.JsonAsync(await client.GetAsync(url));

            foreach (var item in json.GetProperty("items").EnumerateArray())
                seen.Add(item.GetProperty("id").GetString()!);

            cursor = json.GetProperty("next_cursor").ValueKind == JsonValueKind.Null
                ? null
                : json.GetProperty("next_cursor").GetString();

            if (cursor is null) break;
        }

        Assert.Null(cursor);                       // the walk terminated
        Assert.Equal(3, seen.Count);               // every finding
        Assert.Equal(3, seen.Distinct().Count());  // none twice
    }

    [Fact]
    public async Task The_last_page_has_a_null_cursor()
    {
        // How a caller knows to stop. A full page is not evidence more exist, so the absence of
        // a cursor has to be the signal.
        var json = await ReadApiFixture.JsonAsync(
            await Reader().GetAsync($"/v1/scans/{_fixture.ScanJobId}/findings?limit=100"));

        Assert.Equal(3, json.GetProperty("items").GetArrayLength());
        Assert.Equal(JsonValueKind.Null, json.GetProperty("next_cursor").ValueKind);
    }

    [Fact]
    public async Task An_absurd_limit_is_clamped_rather_than_honoured()
    {
        // ?limit=1000000 would otherwise be a denial-of-service one query long.
        var json = await ReadApiFixture.JsonAsync(
            await Reader().GetAsync($"/v1/scans/{_fixture.ScanJobId}/findings?limit=1000000"));

        Assert.Equal(Cursor.MaxLimit, json.GetProperty("limit").GetInt32());
    }

    [Fact]
    public async Task A_malformed_cursor_is_a_bad_request_not_a_crash()
    {
        var response = await Reader()
            .GetAsync($"/v1/scans/{_fixture.ScanJobId}/findings?cursor=not-a-real-cursor");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("layer=code", 1)]
    [InlineData("layer=dep", 1)]
    [InlineData("layer=infra", 1)]
    [InlineData("min_severity=3", 2)]
    [InlineData("min_severity=4", 1)]
    [InlineData("layer=dep&min_severity=4", 1)]
    public async Task Filters_narrow_the_page(string query, int expected)
    {
        var json = await ReadApiFixture.JsonAsync(
            await Reader().GetAsync($"/v1/scans/{_fixture.ScanJobId}/findings?{query}"));

        Assert.Equal(expected, json.GetProperty("items").GetArrayLength());
    }

    [Fact]
    public async Task An_unknown_layer_is_refused_rather_than_silently_matching_nothing()
    {
        // Returning an empty page would read as "this scan has no code findings", which is a
        // different and wrong answer to "that is not a layer".
        var response = await Reader()
            .GetAsync($"/v1/scans/{_fixture.ScanJobId}/findings?layer=banana");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    // ---- RFC 7807 ----------------------------------------------------------------------

    [Fact]
    public async Task Errors_are_problem_json_with_a_stable_type()
    {
        var response = await Reader().GetAsync($"/v1/scans/{Guid.NewGuid()}/findings");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var problem = await ReadApiFixture.JsonAsync(response);

        // The type is the only part a client can branch on safely: titles get reworded, URIs
        // do not.
        Assert.Equal("https://sentinelai.dev/problems/not-found", problem.GetProperty("type").GetString());
        Assert.Equal(404, problem.GetProperty("status").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(problem.GetProperty("detail").GetString()));
    }

    [Fact]
    public async Task A_problem_never_leaks_a_stack_trace()
    {
        // "never raw exception strings" — the design document's words.
        var response = await Reader()
            .GetAsync($"/v1/scans/{_fixture.ScanJobId}/findings?cursor=%%%");

        var body = await response.Content.ReadAsStringAsync();

        Assert.DoesNotContain("at SentinelAI.", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Exception", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Chains_paginate_the_same_way()
    {
        var json = await ReadApiFixture.JsonAsync(
            await Reader().GetAsync($"/v1/scans/{_fixture.ScanJobId}/chains?limit=1"));

        var chain = Assert.Single(json.GetProperty("items").EnumerateArray().ToList());
        Assert.Equal("inferred", chain.GetProperty("min_confidence").GetString());
        Assert.Equal(1, chain.GetProperty("hops").GetArrayLength());
    }
}
