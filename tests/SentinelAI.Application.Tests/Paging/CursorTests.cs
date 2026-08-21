using SentinelAI.Application.Common.Paging;

namespace SentinelAI.Application.Tests.Paging;

/// <summary>
/// The two cursor forms, and the boundary between them.
/// </summary>
/// <remarks>
/// <para>
/// Both are opaque base64url to a caller, which is the point — and also the hazard. Nothing about
/// one <em>looks</em> different from the other, so the only thing stopping a findings cursor being
/// read as a scan-history cursor is that each decoder refuses the other's length.
/// </para>
/// <para>
/// The composite form exists because ordering by a UUIDv7 id is stable but not chronological on
/// SQL Server — see <see cref="Cursor"/>'s own remarks. These tests pin the encoding; the ordering
/// itself is pinned by the list endpoint tests.
/// </para>
/// </remarks>
public class CursorTests
{
    [Fact]
    public void An_id_cursor_round_trips()
    {
        var id = Guid.CreateVersion7();

        Assert.True(Cursor.TryDecode(Cursor.Encode(id), out var decoded));
        Assert.Equal(id, decoded);
    }

    [Fact]
    public void A_composite_cursor_round_trips_both_halves()
    {
        var id = Guid.CreateVersion7();
        var timestamp = new DateTime(2026, 8, 21, 14, 32, 07, DateTimeKind.Utc);

        Assert.True(Cursor.TryDecode(Cursor.Encode(timestamp, id), out var time, out var decodedId));

        Assert.Equal(timestamp, time);
        Assert.Equal(DateTimeKind.Utc, time.Kind);
        Assert.Equal(id, decodedId);
    }

    /// <summary>
    /// Sub-second precision has to survive, or two scans started in the same second page as one
    /// and the id tiebreak never gets a chance to do its job.
    /// </summary>
    [Fact]
    public void A_composite_cursor_keeps_tick_precision()
    {
        var timestamp = new DateTime(2026, 8, 21, 14, 32, 07, DateTimeKind.Utc).AddTicks(1234567);

        Assert.True(Cursor.TryDecode(Cursor.Encode(timestamp, Guid.CreateVersion7()), out var time, out _));
        Assert.Equal(timestamp.Ticks, time.Ticks);
    }

    [Fact]
    public void An_id_cursor_is_not_readable_as_a_composite_one()
    {
        var idOnly = Cursor.Encode(Guid.CreateVersion7());

        Assert.False(Cursor.TryDecode(idOnly, out _, out _));
    }

    [Fact]
    public void A_composite_cursor_is_not_readable_as_an_id_one()
    {
        var composite = Cursor.Encode(DateTime.UtcNow, Guid.CreateVersion7());

        Assert.False(Cursor.TryDecode(composite, out _));
    }

    /// <summary>
    /// A bad cursor is caller error, answered with a 400 — so it returns false rather than
    /// throwing, which is what the single-id decoder already promises.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not base64url!!")]
    [InlineData("AAAA")]
    public void Anything_malformed_is_false_rather_than_an_exception(string? cursor)
    {
        Assert.False(Cursor.TryDecode(cursor, out _));
        Assert.False(Cursor.TryDecode(cursor, out _, out _));
    }

    [Fact]
    public void Clamping_keeps_a_page_size_inside_the_allowed_range()
    {
        Assert.Equal(Cursor.DefaultLimit, Cursor.Clamp(null));
        Assert.Equal(Cursor.DefaultLimit, Cursor.Clamp(0));
        Assert.Equal(Cursor.DefaultLimit, Cursor.Clamp(-5));
        Assert.Equal(Cursor.MaxLimit, Cursor.Clamp(1_000_000));
        Assert.Equal(25, Cursor.Clamp(25));
    }
}
