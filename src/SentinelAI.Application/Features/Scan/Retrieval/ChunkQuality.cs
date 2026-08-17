namespace SentinelAI.Application.Features.Scan.Retrieval;

/// <summary>
/// Why a retrieved chunk was not fit to ground an assertion (SEC-24).
/// </summary>
/// <remarks>
/// Named reasons rather than a bool, because the two defects mean different things about the
/// corpus. A deprecated entry means the <em>ingest</em> filter let something through; a thin one
/// means <c>preprocess.is_over_cleaned</c> did. Collapsing them to "unusable" would drop the only
/// signal saying which loader to go and look at.
/// </remarks>
public enum ChunkDefect
{
    /// <summary>Fit to cite.</summary>
    None,

    /// <summary>The source retired this entry. Its text is a stub that outranks live content.</summary>
    Deprecated,

    /// <summary>Shorter than the ingest's own minimum useful length, so it says nothing.</summary>
    TooThin,
}

/// <summary>
/// SEC-24: the over-fetch-and-filter guard that keeps retired and empty entries out of the debate.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is a second line of defence, and it is meant to be one.</b>
/// <c>PIPELINE_A_CONTEXT.md</c> §7 is explicit: "Deprecated entries are filtered at ingest, not at
/// retrieval… SEC-24 keeps the over-fetch-and-filter guard as belt and braces." On a healthy
/// corpus every method here is a no-op — which is measured, not hoped for. Scrolling the live
/// corpus at <c>corpus_version 2026-08-10-1143</c>:
/// </para>
/// <code>
/// offense 28,950 points   defense 31,179 points
///   status=Deprecated or Obsolete  ....  0 and 0
///   title starting "DEPRECATED"    ....  0 and 0
///   text shorter than 40 chars     ....  0 and 0  (shortest seen: exactly 40)
/// </code>
/// <para>
/// The guard earns its place anyway, because the failure it catches is silent. A retired CAPEC
/// pattern carries two lines of stub text, and short text sits near the centre of the vector space
/// and scores well against almost any query — so a stale corpus does not return an error or an
/// empty list, it returns confident junk at rank one. That is the same failure shape as the
/// missing <c>source</c> condition in <see cref="ExactLookup"/>, and it is caught the same way:
/// by making it impossible to skip rather than by remembering.
/// </para>
///
/// <para><b>Why the filter is client-side.</b></para>
/// <para>
/// Not a preference — Qdrant refuses the alternative. <c>status</c> is a payload field but it is
/// not one of the indexed ones (<c>PIPELINE_A_CONTEXT.md</c> §3), and this cluster rejects a
/// filter on an unindexed key rather than falling back to a scan. Measured against the live
/// corpus: a <c>points/count</c> filtered on <c>status</c> returns <b>HTTP 400</b>, for every
/// value, on both collections. So the condition cannot ride along on the query the way
/// <c>source</c> and <c>content_type</c> do; it has to be applied to results after they come back,
/// which is exactly what the story asks for.
/// </para>
///
/// <para><b>Why the rules are copied from Pipeline A rather than invented here.</b></para>
/// <para>
/// <see cref="DeadStatuses"/> is <c>loaders/capec.py</c> and <c>loaders/cwe.py</c>'s
/// <c>DEAD_STATUS</c>; <see cref="DeprecatedTitleMarker"/> is <c>capec.py</c>'s
/// <c>name.upper().startswith("DEPRECATED")</c>; <see cref="MinimumUsefulCharacters"/> is
/// <c>preprocess.py</c>'s <c>MIN_USEFUL_CHARS</c>. A guard that disagreed with the ingest it is
/// backing up would be worse than no guard: it would either pass what the ingest drops, or drop
/// what the ingest deliberately keeps, and both look like a corpus problem from this side.
/// </para>
/// </remarks>
public static class ChunkQuality
{
    /// <summary>
    /// The <c>status</c> values that mean the source retired this entry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Deprecated and obsolete only. Everything else is live, and the corpus depends on it.</b>
    /// The tempting-looking rule — keep <c>Stable</c>, drop the rest — is catastrophic here, and
    /// the live corpus says by how much:
    /// </para>
    /// <code>
    /// CWE chunks in offense:  Draft 432, Incomplete 486, Stable 26
    /// CAPEC chunks in offense: Draft 723, Stable 299, Usable 4
    /// </code>
    /// <para>
    /// Twenty-six of 944 CWE chunks are <c>Stable</c>. "Only stable" would throw away 97% of the
    /// weakness catalogue — the catalogue every infra and code finding resolves into via the
    /// rule-mapping table. <c>Draft</c> in CAPEC means published-and-usable and is the majority of
    /// the catalogue (<c>capec.py</c> says so in its module docstring, and §7 counts the same 723);
    /// <c>Incomplete</c> in CWE means the entry is still being fleshed out, not withdrawn.
    /// </para>
    /// </remarks>
    public static readonly IReadOnlySet<string> DeadStatuses =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Deprecated", "Obsolete" };

    /// <summary>
    /// MITRE's own marker: a retired entry is renamed <c>DEPRECATED: &lt;old name&gt;</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the only signal that covers ATT&amp;CK.</b> ATT&amp;CK marks retirement with
    /// <c>revoked</c> and <c>x_mitre_deprecated</c>, which are STIX fields the loader reads and
    /// then does not carry into the payload — verified against the live corpus, where no ATT&amp;CK
    /// point has a <c>status</c> key at all. Checking <see cref="DeadStatuses"/> alone would leave
    /// the half of the story's title that says "ATT&amp;CK" unimplemented, and nothing would fail
    /// to say so.
    /// </para>
    /// <para>
    /// Matched as a prefix, not a substring, for the same reason <c>capec.py</c> does: a title that
    /// merely mentions deprecation ("Use of a Deprecated Cryptographic Algorithm") is a live
    /// weakness describing a real problem, and dropping it would be a worse bug than the one being
    /// prevented.
    /// </para>
    /// </remarks>
    public const string DeprecatedTitleMarker = "DEPRECATED";

    /// <summary>
    /// The shortest chunk worth citing, in characters. <c>preprocess.py</c>'s
    /// <c>MIN_USEFUL_CHARS</c>.
    /// </summary>
    /// <remarks>
    /// Pipeline A drops anything shorter at ingest — its <c>is_over_cleaned</c> guard exists
    /// because over-aggressive cleaning leaves stubs like "A flaw allows attackers to.", which the
    /// comment there calls "readable, useless, and silent". The live corpus confirms the constant
    /// binds: the shortest chunk in either collection is exactly 40 characters. This is the same
    /// rule applied at the other end of the pipeline, not a new policy invented at query time.
    /// </remarks>
    public const int MinimumUsefulCharacters = 40;

    /// <summary>
    /// How many chunks to ask for per chunk wanted, so that dropping some still leaves <c>k</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two, not four. The expected drop rate on a healthy corpus is zero, so this is headroom for
    /// a corpus that has gone stale rather than a routine cost — and the outer limit multiplies
    /// through to the inner one, because <c>QdrantKnowledgeSearch</c> prefetches
    /// <c>TopK * PrefetchMultiplier</c> per vector before fusion. At the defaults that is already
    /// 10 → 20 requested → 80 prefetched per vector; a factor of four here would make it 160 for
    /// headroom against a failure that currently never happens.
    /// </para>
    /// <para>
    /// <b>The inner prefetch cannot serve this purpose, which is why there is a second
    /// multiplier.</b> RRF consumes that headroom and emits exactly <c>limit</c> points, so after
    /// fusion there are <c>k</c> and dropping any leaves fewer than <c>k</c>. The dense-only path
    /// settles it: it has no prefetch at all and asks Qdrant for <c>limit</c> directly.
    /// </para>
    /// </remarks>
    public const int OverFetchMultiplier = 2;

    /// <summary>How many chunks to request in order to return <paramref name="topK"/> usable ones.</summary>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="topK"/> is zero or negative.</exception>
    public static int OverFetch(int topK)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(topK);

        return topK * OverFetchMultiplier;
    }

    /// <summary>
    /// Judges one chunk. <see cref="ChunkDefect.None"/> means it is fit to cite.
    /// </summary>
    /// <remarks>
    /// Deprecation is checked before thinness because it is the more specific diagnosis: a retired
    /// entry is usually thin as well, and reporting it as merely short would point at the cleaner
    /// when the loader is what let it through.
    /// </remarks>
    public static ChunkDefect Inspect(KnowledgeChunk chunk)
    {
        ArgumentNullException.ThrowIfNull(chunk);

        if (DeadStatuses.Contains(chunk.Status ?? string.Empty)) return ChunkDefect.Deprecated;

        if (chunk.Title?.TrimStart().StartsWith(DeprecatedTitleMarker, StringComparison.OrdinalIgnoreCase) == true)
            return ChunkDefect.Deprecated;

        // Trimmed, because a chunk padded to length with whitespace is exactly as empty as one
        // that is short. The ingest measures the cleaned text; so does this.
        if ((chunk.Text?.Trim().Length ?? 0) < MinimumUsefulCharacters) return ChunkDefect.TooThin;

        return ChunkDefect.None;
    }

    /// <summary>True when this chunk can support an assertion in the audit.</summary>
    public static bool IsUsable(KnowledgeChunk chunk) => Inspect(chunk) == ChunkDefect.None;

    /// <summary>
    /// Drops the unusable chunks and trims what is left to <paramref name="topK"/>.
    /// </summary>
    /// <param name="chunks">Results as retrieval returned them, best first.</param>
    /// <param name="topK">
    /// How many to keep. Null keeps every survivor — what the exact arm wants, since a payload
    /// filter matches rather than ranks and returns a handful either way.
    /// </param>
    /// <returns>The survivors, still best first, and how many were dropped.</returns>
    /// <remarks>
    /// Order is preserved rather than re-scored. SEC-20's rule holds here too: one authority per
    /// answer. Qdrant ranked these; this method only removes.
    /// </remarks>
    public static QualityFiltered Apply(IReadOnlyList<KnowledgeChunk> chunks, int? topK = null)
    {
        ArgumentNullException.ThrowIfNull(chunks);

        if (topK is { } k) ArgumentOutOfRangeException.ThrowIfNegativeOrZero(k);

        var kept = new List<KnowledgeChunk>(Math.Min(chunks.Count, topK ?? chunks.Count));
        var dropped = 0;

        foreach (var chunk in chunks)
        {
            if (!IsUsable(chunk))
            {
                dropped++;
                continue;
            }

            // Counting past the cap would report chunks as "dropped for quality" when they were
            // really just beyond k, and SEC-25 would read that as corpus rot.
            if (topK is { } cap && kept.Count == cap) break;

            kept.Add(chunk);
        }

        return new QualityFiltered(kept, dropped);
    }
}

/// <summary>
/// What survived <see cref="ChunkQuality.Apply"/>, and how much did not.
/// </summary>
/// <param name="Chunks">The usable chunks, best first, capped at the requested count.</param>
/// <param name="Dropped">How many were removed for a defect. Zero on a healthy corpus.</param>
/// <remarks>
/// The count is returned rather than logged inside the filter because the filter is pure and the
/// caller is the one that knows which finding was being grounded. A drop is worth saying out loud:
/// it is the only evidence that the corpus has gone stale, and on a healthy one it never appears.
/// </remarks>
public sealed record QualityFiltered(IReadOnlyList<KnowledgeChunk> Chunks, int Dropped)
{
    /// <summary>True when something was removed — the only case worth logging.</summary>
    public bool AnyDropped => Dropped > 0;

    /// <summary>
    /// True when everything retrieved was unusable, so this arm answered with nothing.
    /// </summary>
    /// <remarks>
    /// Distinct from "retrieved nothing". The corpus <em>had</em> something and it was not fit to
    /// cite, which is a different problem with a different fix, and
    /// <see cref="RetrievalMiss.NothingUsable"/> is how the difference reaches the audit.
    /// </remarks>
    public bool EverythingDropped => Dropped > 0 && Chunks.Count == 0;
}
