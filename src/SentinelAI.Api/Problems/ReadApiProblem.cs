using Microsoft.AspNetCore.Mvc;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Api.Problems;

/// <summary>
/// RFC 7807 <c>application/problem+json</c> responses for the read API (SEC-40).
/// </summary>
/// <remarks>
/// <para>
/// The API design document requires "a stable <c>type</c> and <c>detail</c> — never raw
/// exception strings". The <c>type</c> matters most: it is the only part a client can branch
/// on safely. Human-readable text gets reworded; a URI does not, so a screen that wants to
/// show "this scan was purged" differently from "this scan does not exist" has something
/// reliable to switch on.
/// </para>
/// <para>
/// Applied to the read endpoints only. The rest of the API answers with the <see cref="Response"/>
/// envelope, and converting it wholesale would change error bodies for auth, ingest and project
/// endpoints that other work depends on. Two formats is a real inconsistency and it is written
/// down in <c>docs/Read_API.md</c> rather than left to be discovered.
/// </para>
/// </remarks>
public static class ReadApiProblem
{
    /// <summary>Base for every problem type this API emits. Stable across versions.</summary>
    private const string TypeBase = "https://sentinelai.dev/problems/";

    public static ObjectResult NotFound(HttpContext http, string detail) =>
        Build(http, StatusCodes.Status404NotFound, "not-found", "Resource not found", detail);

    public static ObjectResult Unauthorized(HttpContext http, string detail) =>
        Build(http, StatusCodes.Status401Unauthorized, "unauthorized", "Authentication required", detail);

    public static ObjectResult Forbidden(HttpContext http, string detail) =>
        Build(http, StatusCodes.Status403Forbidden, "forbidden", "Insufficient permissions", detail);

    public static ObjectResult BadRequest(HttpContext http, string detail) =>
        Build(http, StatusCodes.Status400BadRequest, "invalid-request", "Invalid request", detail);

    /// <summary>
    /// The result is too large to return whole. Used by the graph endpoint, which cannot be
    /// paginated meaningfully — see <c>GetGraphQueryHandler</c>.
    /// </summary>
    public static ObjectResult TooLarge(HttpContext http, string detail) =>
        Build(http, StatusCodes.Status413PayloadTooLarge, "result-too-large", "Result too large", detail);

    /// <summary>The bundle was purged under the retention policy (SEC-35), so it is gone for good.</summary>
    public static ObjectResult Gone(HttpContext http, string detail) =>
        Build(http, StatusCodes.Status410Gone, "purged", "Resource purged", detail);

    /// <summary>
    /// Translates an application-layer <see cref="Response"/> failure into problem+json.
    /// </summary>
    /// <remarks>
    /// The handlers return <see cref="Response"/> like every other feature in this codebase —
    /// the read endpoints differ only in how a failure is <em>rendered</em>, not in how it is
    /// produced. Keeping the translation at the edge means the Application layer stays free of
    /// HTTP representation concerns.
    /// </remarks>
    public static ObjectResult From(HttpContext http, Response response)
    {
        var status = (int)response.StatusCode;
        var detail = string.IsNullOrWhiteSpace(response.Message) ? "The request could not be completed." : response.Message;

        return status switch
        {
            StatusCodes.Status401Unauthorized => Unauthorized(http, detail),
            StatusCodes.Status403Forbidden => Forbidden(http, detail),
            StatusCodes.Status404NotFound => NotFound(http, detail),
            StatusCodes.Status400BadRequest => BadRequest(http, detail),
            StatusCodes.Status410Gone => Gone(http, detail),
            StatusCodes.Status413PayloadTooLarge => TooLarge(http, detail),
            _ => Build(http, status, "error", "Request failed", detail),
        };
    }

    private static ObjectResult Build(HttpContext http, int status, string slug, string title, string detail)
    {
        var problem = new ProblemDetails
        {
            Type = TypeBase + slug,
            Title = title,
            Status = status,
            Detail = detail,
            Instance = http.Request.Path,
        };

        return new ObjectResult(problem)
        {
            StatusCode = status,
            ContentTypes = { "application/problem+json" },
        };
    }
}
