using System.Buffers.Binary;
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
/// Keyset paging on the id is <b>stable</b> because every id is <c>Guid.CreateVersion7</c> and the
/// <c>WHERE</c> and <c>ORDER BY</c> use the same comparison, so a page never repeats or skips a
/// row. That is all a per-scan list needs, and it is why <c>/findings</c> and <c>/chains</c> page
/// this way.
/// </para>
/// <para>
/// It is <b>not chronological on SQL Server</b>, and an earlier version of this comment said it
/// was. UUIDv7 is time-ordered in its bytes, but <c>uniqueidentifier</c> collation compares the
/// trailing node bytes before the leading timestamp bytes, so <c>ORDER BY Id</c> is close to
/// random with respect to time. Two v7 ids demonstrate it: <c>01a025b8-…-ffffffffffff</c> was
/// generated before <c>01a025b9-…-000000000000</c>, and SQL Server sorts the later one first.
/// Nothing in the test suite catches this — the integration tests run on the EF in-memory
/// provider, where <c>Guid.CompareTo</c> gives a third order again.
/// </para>
/// <para>
/// So any list that promises an order <em>by time</em> — the scan history, the audit list — must
/// page on its timestamp with the id only as a tiebreak. See
/// <see cref="Cursor.Encode(DateTime, Guid)"/>.
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

    /// <summary>
    /// Encodes a keyset cursor over <c>(timestamp, id)</c> — for a list ordered by time rather
    /// than by id. Twenty-four bytes: eight of ticks, sixteen of guid.
    /// </summary>
    /// <remarks>
    /// See this type's remarks for why the single-id form cannot carry a chronological order on
    /// SQL Server. The id is still here, as the tiebreak between two rows sharing a timestamp;
    /// it decides nothing on its own.
    /// </remarks>
    public static string Encode(DateTime lastTimestampUtc, Guid lastId)
    {
        Span<byte> bytes = stackalloc byte[CompositeLength];
        BinaryPrimitives.WriteInt64BigEndian(bytes, lastTimestampUtc.Ticks);
        lastId.TryWriteBytes(bytes[sizeof(long)..]);

        return Base64Url.EncodeToString(bytes);
    }

    /// <summary>
    /// Reads a composite cursor.
    /// </summary>
    /// <remarks>
    /// A cursor of any other length — notably the sixteen-byte <see cref="Encode(Guid)"/> form —
    /// is refused rather than reinterpreted. Both are opaque base64url to a caller, so pasting one
    /// where the other belongs is an easy mistake; length is what makes it a 400 instead of a page
    /// of plausible-looking wrong rows.
    /// </remarks>
    public static bool TryDecode(string? cursor, out DateTime lastTimestampUtc, out Guid lastId)
    {
        lastTimestampUtc = default;
        lastId = Guid.Empty;
        if (string.IsNullOrWhiteSpace(cursor)) return false;

        try
        {
            var bytes = Base64Url.DecodeFromChars(cursor);
            if (bytes.Length != CompositeLength) return false;

            var ticks = BinaryPrimitives.ReadInt64BigEndian(bytes);
            if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks) return false;

            lastTimestampUtc = new DateTime(ticks, DateTimeKind.Utc);
            lastId = new Guid(bytes.AsSpan(sizeof(long)));
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Eight bytes of ticks followed by sixteen of guid.</summary>
    private const int CompositeLength = sizeof(long) + 16;
}
