using System.Text.RegularExpressions;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Debate;

/// <summary>
/// The one deterministic fact-check the debate gets: does a hop Red asserted correspond to a
/// real edge, and in which direction (SEC-50).
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> A live run asserted <c>N3 -&gt; assumes -&gt; N69</c>; the resource
/// graph's real edge is <c>N69 --assumes--&gt; N3</c> — reversed. Blue's own validation replied
/// "CONFIRMED, edge exists in given edges," the chain converged, and the reversed edge reached
/// the Reporter's final draft audit as a real finding. Nothing forced that to be caught: Red's
/// and Blue's entire shared understanding of "what edges exist" is one text list, read twice, by
/// two calls to the same kind of model. This is the check that does not trust either reading.
/// </para>
/// <para>
/// <b>What it deliberately does not do.</b> It does not parse the asserted <em>technique</em> or
/// <em>evidence</em> — free text, no ground truth to check it against. It does not decide the
/// chain is fake — a hop it cannot classify is reported, not discarded, exactly like an edge
/// Blue could not confirm is surfaced rather than dropped (AID-01 §3.3). The one thing it checks
/// is the one thing that has an answer outside the model's own prose: whether a node pair the
/// text names is an edge the brief actually listed, in either direction.
/// </para>
/// <para>
/// <b>Ground truth is the brief text, not a database.</b> <c>POST /v1/debates</c> takes the
/// resource graph as free text from a caller with no persisted <see cref="GraphEdge"/> row
/// behind it at all. Parsing the same "Edges: ..." section <c>ScanBriefRenderer</c> wrote
/// — the section the model itself read — is what lets one check cover every caller of
/// <c>IDebateEngine</c> instead of only the ones with a graph in the database.
/// </para>
/// </remarks>
public static class EdgeAssertionValidator
{
    /// <summary>Node-key label pattern the rest of the brief is written in: <c>N12</c>, never <c>n12</c>.</summary>
    private static readonly Regex NodeToken = new(@"\bN(\d+)\b", RegexOptions.Compiled);

    /// <summary>Matches one line <see cref="Graph.ScanBriefRenderer"/>'s edge section writes: <c>  N3 --can-access--> N65 (certain)</c>.</summary>
    private static readonly Regex RenderedEdge = new(
        @"\bN(?<from>\d+)\s*--[^>]*-->\s*N(?<to>\d+)", RegexOptions.Compiled);

    /// <summary>Matches the brief's own node list entry: <c>N65=code:orderapp</c>, optionally followed by <c> HOT</c>.</summary>
    private static readonly Regex NodeLabelDeclaration = new(
        @"\bN(?<index>\d+)=(?<label>[^\s|]+)", RegexOptions.Compiled);

    /// <summary>Matches an agent's inline node annotation: <c>N65:code:orderapp</c>.</summary>
    private static readonly Regex NodeLabelClaim = new(
        @"\bN(?<index>\d+):(?<label>[\w./:\-]+)", RegexOptions.Compiled);

    public enum HopStatus
    {
        /// <summary>The pair matches a real edge in the asserted direction.</summary>
        Confirmed,

        /// <summary>The pair matches a real edge, but only in the opposite direction.</summary>
        Reversed,

        /// <summary>No real edge joins this pair, in either direction.</summary>
        Unrecognized,
    }

    public sealed record HopFinding(string From, string To, HopStatus Status)
    {
        public string Describe() => Status switch
        {
            HopStatus.Reversed =>
                $"Asserted hop {From} -> {To} does not match the graph — the real edge runs {To} -> {From}.",
            HopStatus.Unrecognized =>
                $"Asserted hop {From} -> {To} does not correspond to any edge in the resource graph.",
            _ => $"{From} -> {To} confirmed.",
        };
    }

    /// <summary>
    /// Checks every node-reference pair joined by an arrow in <paramref name="assertedText"/>
    /// against the edges parsed out of <paramref name="briefContext"/>. Returns every pair it
    /// found, <see cref="HopStatus.Confirmed"/> included — callers filter for what they need.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Extraction is deliberately loose about the relation word: every line is scanned for
    /// <c>N&lt;digits&gt;</c> tokens in order, and each consecutive pair is a candidate hop. This
    /// survives every format the two agents have actually produced —
    /// <c>N3 -&gt; can-access -&gt; N65</c>, <c>N3:pkg:x -&gt; technique:used-by -&gt;
    /// evidence:N8:pkg:y</c>, <c>N30 -&gt; used-by -&gt; N1: CONFIRMED, edge N30 --used-by--&gt;
    /// N1 exists.</c> — because it never needs to parse the relation word between them, only the
    /// two node references naming the hop's endpoints.
    /// </para>
    /// <para>
    /// <b>It is not loose about there being an arrow at all.</b> A live Reporter turn wrote
    /// <c>Chain confirmed: N8 -&gt; N1 -&gt; N69 -&gt; N3 -&gt; N65, N66</c> — the comma before
    /// <c>N66</c> lists a second branch target from <c>N3</c>, not a hop from <c>N65</c>. Pairing
    /// every consecutive token regardless of what separates them would read that comma as an
    /// asserted edge nobody claimed, which is a fabrication the check itself would be
    /// introducing. A pair is only a candidate hop when the text between the two tokens contains
    /// <c>-&gt;</c>.
    /// </para>
    /// </remarks>
    public static IReadOnlyList<HopFinding> Validate(string briefContext, string assertedText)
    {
        if (string.IsNullOrWhiteSpace(briefContext) || string.IsNullOrWhiteSpace(assertedText))
            return [];

        var realEdges = ParseRealEdges(briefContext);
        if (realEdges.Count == 0) return [];

        var found = new Dictionary<(int From, int To), HopStatus>();

        foreach (var line in assertedText.Split('\n'))
        {
            foreach (var (from, to) in ArrowJoinedPairs(line, AsciiArrow))
            {
                var key = (from, to);
                if (found.ContainsKey(key)) continue; // first classification wins; duplicates are noise

                found[key] = realEdges.Contains((from, to)) ? HopStatus.Confirmed
                    : realEdges.Contains((to, from)) ? HopStatus.Reversed
                    : HopStatus.Unrecognized;
            }
        }

        return [.. found.Select(kv => new HopFinding($"N{kv.Key.From}", $"N{kv.Key.To}", kv.Value))];
    }

    /// <summary>The arrow spelling this validator pairs on. Exactly what it has always used.</summary>
    /// <remarks>
    /// Kept as the narrow default deliberately. <see cref="HopVerdictReader"/> pairs on a wider
    /// set, and widening it <em>here</em> would silently change which hops get reported as
    /// unconfirmed — that is a change to what caps a chain at <c>Asserted</c> (SEC-50), not a
    /// parsing tidy-up, and it does not belong in a ticket about per-hop fields.
    /// </remarks>
    internal static readonly string[] AsciiArrow = ["->"];

    /// <summary>
    /// Every ordered pair of node references on one line that has an arrow between them, in
    /// the order they appear.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Extracted so the per-hop reader (audit 42-A) anchors on hops the same way this validator
    /// always has, rather than growing a second, subtly different idea of what a hop line is.
    /// Both callers therefore inherit the same two hard-won rules:
    /// </para>
    /// <para>
    /// <b>The relation word is never parsed</b> — only the two node references around it. That
    /// is what survives every format the agents have actually produced:
    /// <c>N3 -&gt; can-access -&gt; N65</c>, <c>N3:pkg:x -&gt; technique:used-by -&gt;
    /// evidence:N8:pkg:y</c>, <c>N30 -&gt; used-by -&gt; N1: CONFIRMED, edge N30 --used-by--&gt;
    /// N1 exists.</c>
    /// </para>
    /// <para>
    /// <b>An arrow must actually be there.</b> A live Reporter turn wrote
    /// <c>Chain confirmed: N8 -&gt; N1 -&gt; N69 -&gt; N3 -&gt; N65, N66</c>, where the comma
    /// lists a second branch target from <c>N3</c> rather than a hop out of <c>N65</c>. Pairing
    /// on adjacency alone would invent that hop.
    /// </para>
    /// </remarks>
    internal static IEnumerable<(int From, int To)> ArrowJoinedPairs(string line, string[] arrows)
    {
        var matches = NodeToken.Matches(line);
        if (matches.Count < 2) yield break;

        for (var i = 0; i < matches.Count - 1; i++)
        {
            if (!TryIndex(matches[i], out var from) || !TryIndex(matches[i + 1], out var to))
                continue;

            if (from == to) continue;

            var between = line[(matches[i].Index + matches[i].Length)..matches[i + 1].Index];
            if (!arrows.Any(a => between.Contains(a, StringComparison.Ordinal))) continue;

            yield return (from, to);
        }
    }

    /// <summary>
    /// The brief's own node declarations — <c>N65=code:orderapp</c> — as index to canonical
    /// node key.
    /// </summary>
    /// <remarks>
    /// The one place the <c>N&lt;n&gt;</c> labels the agents write can be turned back into
    /// something the database knows about. It is read out of the brief text rather than
    /// re-derived by re-querying the nodes in the hope of getting the same order back: the
    /// numbering is positional in whatever list <c>ScanBriefRenderer</c> was handed, and a query
    /// with no <c>ORDER BY</c> is not a promise to return that order again. Same principle as
    /// this class's own ground truth — the text the model read is the text we check against.
    /// </remarks>
    public static IReadOnlyDictionary<int, string> DeclaredNodeKeys(string briefContext)
    {
        var declared = new Dictionary<int, string>();
        if (string.IsNullOrWhiteSpace(briefContext)) return declared;

        foreach (Match m in NodeLabelDeclaration.Matches(briefContext))
        {
            if (int.TryParse(m.Groups["index"].Value, out var index))
                declared[index] = m.Groups["label"].Value;
        }

        return declared;
    }

    /// <summary>Only the hops worth a human's attention — a clean transcript returns nothing.</summary>
    public static IReadOnlyList<string> UnconfirmedDescriptions(string briefContext, string assertedText) =>
        [.. Validate(briefContext, assertedText)
            .Where(f => f.Status != HopStatus.Confirmed)
            .Select(f => f.Describe())];

    public sealed record NodeLabelFinding(string NodeRef, string ClaimedLabel, string RealLabel)
    {
        public string Describe() =>
            $"{NodeRef} is asserted as '{ClaimedLabel}' but the resource graph's real {NodeRef} is '{RealLabel}'.";
    }

    /// <summary>
    /// Checks every inline node annotation an agent writes — <c>N65:code:orderapp</c> — against
    /// the brief's own <c>N65=code:orderapp</c> declaration. An agent can name a structurally
    /// real edge pair while still fabricating what one of the endpoints <em>is</em>; this is the
    /// check for that, separate from <see cref="Validate"/> because a wrong label and a wrong
    /// edge are different claims; a hop can have a real, correctly-directed edge between two
    /// nodes whose identities were still misstated by the very message reporting them.
    /// </summary>
    public static IReadOnlyList<NodeLabelFinding> ValidateNodeLabels(string briefContext, string assertedText)
    {
        if (string.IsNullOrWhiteSpace(briefContext) || string.IsNullOrWhiteSpace(assertedText))
            return [];

        var realLabels = DeclaredNodeKeys(briefContext);
        if (realLabels.Count == 0) return [];

        var found = new Dictionary<int, NodeLabelFinding>();
        foreach (Match m in NodeLabelClaim.Matches(assertedText))
        {
            if (!int.TryParse(m.Groups["index"].Value, out var index) || found.ContainsKey(index))
                continue;

            // An index the brief never declared is out of range for this scan's node count —
            // not this check's job; Validate's edge check has nothing to match it against either.
            if (!realLabels.TryGetValue(index, out var real)) continue;

            var claimed = m.Groups["label"].Value.TrimEnd('.', ',', ':');
            if (!string.Equals(claimed, real, StringComparison.Ordinal))
                found[index] = new NodeLabelFinding($"N{index}", claimed, real);
        }

        return [.. found.Values];
    }

    private static bool TryIndex(Match m, out int index) => int.TryParse(m.Groups[1].Value, out index);

    private static HashSet<(int From, int To)> ParseRealEdges(string briefContext)
    {
        var edges = new HashSet<(int, int)>();

        foreach (Match m in RenderedEdge.Matches(briefContext))
        {
            if (int.TryParse(m.Groups["from"].Value, out var from) &&
                int.TryParse(m.Groups["to"].Value, out var to))
                edges.Add((from, to));
        }

        return edges;
    }
}
