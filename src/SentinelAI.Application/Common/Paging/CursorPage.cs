using System.Buffers.Text;
using System.Text.Json.Serialization;

namespace SentinelAI.Application.Common.Paging;

/// <summary>
/// One page of a list endpoint, plus the cursor that fetches the next one (SEC-40).
/// </summary>
/// <remarks>
/// <para>
/// Cursor paging rather than <c>?page=2</c>, as the API design document specifies. With an
/// offset, rows inserted or deleted between requests shift everything after them: page 2 can
/// repeat a row page 1 already returned, or skip one entirely. A cursor names the last row the
/// caller actually saw, so the next page starts after that row whatever else has changed.
/// </para>
/// <para>
/// <c>next_cursor</c> is null on the last page. That — not an item count — is how a caller
/// knows to stop, because a full page is not evidence that more exist.
/// </para>
/// </remarks>
public sealed record CursorPage<T>
{
    [JsonPropertyName("items")]
    public required IReadOnlyList<T> Items { get; init; }

    /// <summary>Pass back as <c>?cursor=</c> for the next page. Null means this was the last.</summary>
    [JsonPropertyName("next_cursor")]
    public string? NextCursor { get; init; }

    [JsonPropertyName("limit")]
    public required int Limit { get; init; }

    public static CursorPage<T> Of(IReadOnlyList<T> items, string? nextCursor, int limit) =>
        new() { Items = items, NextCursor = nextCursor, Limit = limit };

    public static CursorPage<T> Empty(int limit) =>
        new() { Items = [], NextCursor = null, Limit = limit };
}

/// <summary>
/// Encodes and decodes the opaque page cursor.
/// </summary>
/// <remarks>
/// <para>
/// The cursor is the id of the last row on the page, base64url-encoded. It is deliberately
/// opaque: a caller that parses it starts depending on it being an id, and the day a query
/// needs to sort on something else every client breaks. Encoding also stops it reading like a
/// database key someone might try substituting — though it is <em>not</em> a security boundary,
/// which is why every query still filters by tenant and scan job independently of it.
/// </para>
/// <para>
/// Keyset paging on the id works here because every id is <c>Guid.CreateVersion7</c> — UUIDv7 is
/// time-ordered, so ordering by id is both stable and chronological. With random UUIDv4 keys
/// this technique would produce an arbitrary order, and "the next page" would mean nothing.
/// </para>
/// </remarks>
public static class Cursor
{
    /// <summary>Default page size when the caller does not ask for one.</summary>
    public const int DefaultLimit = 50;

    /// <summary>
    /// Largest page a caller may request. Without a ceiling, <c>?limit=1000000</c> is a
    /// denial-of-service one query long.
    /// </summary>
    public const int MaxLimit = 200;

    /// <summary>Clamps a requested page size into the allowed range.</summary>
    public static int Clamp(int? limit) => limit switch
    {
        null or <= 0 => DefaultLimit,
        > MaxLimit => MaxLimit,
        _ => limit.Value,
    };

    public static string Encode(Guid lastId) =>
        Base64Url.EncodeToString(lastId.ToByteArray());

    /// <summary>
    /// Reads a cursor. Returns false for anything malformed rather than throwing — a bad
    /// cursor is caller error, answered with a 400, not a 500.
    /// </summary>
    public static bool TryDecode(string? cursor, out Guid lastId)
    {
        lastId = Guid.Empty;
        if (string.IsNullOrWhiteSpace(cursor)) return false;

        try
        {
            var bytes = Base64Url.DecodeFromChars(cursor);
            if (bytes.Length != 16) return false;

            lastId = new Guid(bytes);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }
}
