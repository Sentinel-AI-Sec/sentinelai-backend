using System.Text.RegularExpressions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Application.Debate;

/// <summary>
/// One hop of an asserted chain, as it can be read out of an agent's turn and checked back
/// against the brief that turn answered.
/// </summary>
/// <param name="Order">1-based position in the turn, in the order the lines were written.</param>
/// <param name="From">The <c>N&lt;n&gt;</c> label the agent wrote for the source node.</param>
/// <param name="To">The <c>N&lt;n&gt;</c> label the agent wrote for the target node.</param>
/// <param name="FromLabel">
/// The canonical node key the <em>brief</em> declared for <paramref name="From"/> — never the
/// label the agent claimed inline. An agent can name a real edge while misstating what one of
/// its endpoints is, and that disagreement is reported separately by
/// <see cref="EdgeAssertionValidator.ValidateNodeLabels"/>; showing the agent's version here
/// would launder it into the answer. Null when the brief declared no such node.
/// </param>
/// <param name="ToLabel">As <paramref name="FromLabel"/>, for the target node.</param>
/// <param name="Relation">
/// The relation word between the two node references — <c>used-by</c>, <c>assumes</c>. Free
/// text: nothing checks it against the graph's own relation, so it is shown, not trusted.
/// </param>
/// <param name="Technique">
/// The ATT&amp;CK id Red named for this hop, kept only where the brief itself contains it
/// (see <see cref="HopVerdictReader.ReadTechniques"/>). Null when none was named or the one
/// named was recalled rather than read.
/// </param>
/// <param name="Verdict">
/// Blue's judgement of this hop. <see cref="HopVerdict.Unattributed"/> — the default — means
/// nothing in the turn could be tied to this hop, which is not a judgement and must not render
/// as one.
/// </param>
/// <param name="GraphStatus">
/// The one deterministic fact-check available: whether the brief actually lists this edge, and
/// in which direction. See <see cref="TurnPresenter.HopGraphStatus"/>.
/// </param>
/// <param name="Evidence">Whatever the agent wrote after the hop, trimmed of the tokens above.</param>
/// <param name="Text">The whole line, unmodified, so nothing below is unfalsifiable.</param>
public sealed record TurnHopView(
    int Order,
    string From,
    string To,
    string? FromLabel,
    string? ToLabel,
    string? Relation,
    string? Technique,
    string Verdict,
    string GraphStatus,
    string? Evidence,
    string Text);

/// <summary>A labelled line an agent wrote: <c>SEVERITY: HIGH</c> becomes label + value.</summary>
public sealed record TurnFactView(string Label, string Value);

/// <summary>
/// One agent's turn, taken apart into the things it actually claimed.
/// </summary>
/// <remarks>
/// Every field may be empty, and all of them being empty is a valid, expected outcome — it means
/// the model wrote prose this cannot structure. Callers must keep rendering the raw turn text
/// alongside this, never instead of it.
/// </remarks>
/// <param name="Headline">The turn's opening sentence of prose, if it wrote one.</param>
/// <param name="Hops">The chain, in the order asserted.</param>
/// <param name="Facts">Labelled lines, in the order written.</param>
/// <param name="Notes">Every other line of prose.</param>
/// <param name="Verdict">
/// Blue's closing verdict — <c>CHAIN_HOLDS</c>, <c>CHAIN_BROKEN</c>, or <c>UNREADABLE</c> when
/// no verdict could be parsed at all. Null for the other three agents, which do not give one.
/// </param>
public sealed record TurnDisplay(
    string? Headline,
    IReadOnlyList<TurnHopView> Hops,
    IReadOnlyList<TurnFactView> Facts,
    IReadOnlyList<string> Notes,
    string? Verdict)
{
    /// <summary>Nothing could be structured out of the turn; render the raw text alone.</summary>
    public bool IsEmpty =>
        Headline is null && Hops.Count == 0 && Facts.Count == 0 && Notes.Count == 0 && Verdict is null;

    public static TurnDisplay Empty { get; } = new(null, [], [], [], null);
}

/// <summary>
/// Turns one agent's free text into the structure the transcript is <em>about</em>: a chain of
/// hops, each with the brief's own name for its endpoints, Blue's verdict on it, the ATT&amp;CK
/// id Red grounded it in, and whether the graph really has that edge.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why the presentation is computed here and not in the client.</b> Two of the four things
/// worth showing about a hop — the verdict and the technique — are recovered by rules that took
/// several live failures to get right (see <see cref="HopVerdictReader"/>), and a third is a
/// fact-check against the brief (<see cref="EdgeAssertionValidator"/>). Re-deriving any of that
/// in TypeScript would mean two parsers disagreeing about what an agent said, which is a worse
/// failure than not parsing at all: the screen would contradict the database.
/// </para>
/// <para>
/// <b>It anchors hops exactly the way the checkers do.</b> A line is a hop line when it names
/// exactly one pair of brief-declared nodes with an arrow between them — the shared rule in
/// <see cref="EdgeAssertionValidator.ArrowJoinedPairs"/>. A line naming two hops, or none, is
/// prose. That is the same refusal the readers make, so a hop rendered here is a hop the
/// verdict reader also saw, and the two cannot drift.
/// </para>
/// <para>
/// <b>Nothing is inferred.</b> No field is defaulted to a plausible value. A hop Blue said
/// nothing attributable about is <see cref="HopVerdict.Unattributed"/>, an edge the brief does
/// not list is <c>unrecognized</c>, and a missing technique is null — never a guess, and never a
/// silently reassuring value.
/// </para>
/// </remarks>
public static class TurnPresenter
{
    /// <summary>Arrow spellings a hop line may use, matching <see cref="HopVerdictReader"/>'s.</summary>
    private static readonly string[] Arrows = ["->", "→"];

    /// <summary>What the deterministic edge check said about a hop.</summary>
    public static class HopGraphStatus
    {
        /// <summary>The brief lists this edge in the direction asserted.</summary>
        public const string Confirmed = "confirmed";

        /// <summary>The brief lists this edge, but running the other way.</summary>
        public const string Reversed = "reversed";

        /// <summary>The brief lists no edge between these two nodes at all.</summary>
        public const string Unrecognized = "unrecognized";

        /// <summary>
        /// The check did not classify this pair — the line used an arrow spelling the validator
        /// deliberately does not pair on. Absence of a check, not a clean result.
        /// </summary>
        public const string Unchecked = "unchecked";
    }

    /// <summary>Blue's readable verdicts, spelled as its instructions mandate them.</summary>
    private const string ChainHolds = "CHAIN_HOLDS";
    private const string ChainBroken = "CHAIN_BROKEN";

    /// <summary>What a turn with no parseable verdict token reports, for Blue only.</summary>
    public const string VerdictUnreadable = "UNREADABLE";

    /// <summary>
    /// A labelled line: <c>SEVERITY: HIGH</c>, <c>WEAK JOIN: N2 -&gt; N4</c>.
    /// </summary>
    /// <remarks>
    /// Upper case is the whole signal. The four agents are instructed to label their lines that
    /// way, and requiring it is what stops an ordinary sentence containing a colon ("Note: the
    /// image tag is mutable") from being promoted into a field. The label is capped at a few
    /// words so a whole clause cannot become one.
    /// </remarks>
    private static readonly Regex LabelledLine =
        new(@"^(?<label>[A-Z][A-Z0-9]*(?:[ &/-][A-Z0-9]+){0,2}):\s*(?<value>\S.*)$", RegexOptions.Compiled);

    /// <summary>
    /// The one label that introduces a hop rather than a field, as Red's and Blue's
    /// instructions spell it: <c>HOP 3: …</c>.
    /// </summary>
    private const string HopLabel = "HOP";

    /// <summary>A line whose only content is Blue's closing verdict token.</summary>
    private static readonly Regex VerdictLine =
        new(@"^(?:VERDICT\s*:\s*)?(?:CHAIN_HOLDS|CHAIN_BROKEN)\.?$", RegexOptions.Compiled);

    /// <summary>Blue's per-hop vocabulary, so it can be lifted out of a hop line's evidence.</summary>
    private static readonly Regex VerdictToken =
        new(@"\b(?:CONFIRMED|UNRESOLVED|REFUTED)\b", RegexOptions.Compiled);

    /// <summary>An ATT&amp;CK id, matching <see cref="HopVerdictReader"/>'s shape.</summary>
    private static readonly Regex TechniqueToken =
        new(@"\bT\d{4}(?:\.\d{3})?\b", RegexOptions.Compiled);

    /// <summary>The prompt keywords the agents put in front of a hop's parts.</summary>
    private static readonly Regex HopKeyword =
        new(@"\b(?:hop|technique|evidence|via|relation)\s*[:=]?\s*", RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>Words too few to be a headline — a fragment left over from a stripped line.</summary>
    private const int MinHeadlineWords = 3;

    /// <summary>
    /// Reads one turn against the brief it answered.
    /// </summary>
    /// <param name="briefContext">
    /// The rendered resource graph the agent was given. This is the ground truth for node names
    /// and edges — the same text the model read, not a re-query of the database, for the reason
    /// <see cref="EdgeAssertionValidator.DeclaredNodeKeys"/> spells out.
    /// </param>
    /// <param name="turn">The turn to read.</param>
    public static TurnDisplay Present(string? briefContext, DebateTurn turn)
    {
        ArgumentNullException.ThrowIfNull(turn);

        var content = TranscriptText.Clean(turn.Content);
        var verdict = ClosingVerdict(turn);

        if (content.Length == 0)
            return verdict is null ? TurnDisplay.Empty : TurnDisplay.Empty with { Verdict = verdict };

        var brief = briefContext ?? string.Empty;
        var declared = EdgeAssertionValidator.DeclaredNodeKeys(brief);
        var verdicts = HopVerdictReader.ReadVerdicts(brief, content);
        var techniques = HopVerdictReader.ReadTechniques(brief, content);
        var graphStatus = GraphStatusByPair(brief, content);

        var hops = new List<TurnHopView>();
        var facts = new List<TurnFactView>();
        var notes = new List<string>();
        string? headline = null;

        foreach (var line in content.Split('\n'))
        {
            if (line.Length == 0) continue;

            if (VerdictLine.IsMatch(line)) continue; // reported as Verdict, not as a note

            // The label decides first, and only a HOP label opens the door to a hop reading.
            // The agents write node pairs inside fields all the time — "CONFIDENCE: unresolved
            // — the weakest join is N2 -> N4", "WEAK JOIN: N2 -> N4" — and reading the hop
            // first turned every one of those into an asserted hop the agent never asserted.
            var labelled = LabelledLine.Match(line);
            var labelsAHop = labelled.Success
                && labelled.Groups["label"].Value.StartsWith(HopLabel, StringComparison.Ordinal);

            if ((!labelled.Success || labelsAHop)
                && TryReadHop(line, declared, verdicts, techniques, graphStatus, hops.Count + 1) is { } hop)
            {
                hops.Add(hop);
                continue;
            }

            if (labelled.Success)
            {
                facts.Add(new TurnFactView(
                    labelled.Groups["label"].Value,
                    labelled.Groups["value"].Value.Trim()));
                continue;
            }

            if (headline is null && WordCount(line) >= MinHeadlineWords)
            {
                headline = line;
                continue;
            }

            notes.Add(line);
        }

        return new TurnDisplay(headline, hops, facts, notes, verdict);
    }

    /// <summary>
    /// Blue's closing verdict, taken from the turn's own flags rather than re-parsed.
    /// </summary>
    /// <remarks>
    /// <c>BlueTeamExecutor</c> already reads the verdict, through fallbacks earned by live runs
    /// that wrote it four different ways, and the debate's routing is decided by what it read.
    /// Parsing the text a second time here could disagree with that — the screen would say the
    /// chain broke while the workflow proceeded as though it held. So this reports the decision
    /// that was actually acted on, including its failure case.
    /// </remarks>
    private static string? ClosingVerdict(DebateTurn turn) => turn.Role switch
    {
        AgentRole.Blue when !turn.VerdictReadable => VerdictUnreadable,
        AgentRole.Blue => turn.Converged ? ChainHolds : ChainBroken,
        _ => null,
    };

    /// <summary>
    /// The deterministic edge check's answer for every pair it classified, keyed by
    /// <c>("N1", "N2")</c> as the validator itself spells them.
    /// </summary>
    private static Dictionary<(string From, string To), string> GraphStatusByPair(
        string brief, string content)
    {
        var byPair = new Dictionary<(string, string), string>();

        foreach (var finding in EdgeAssertionValidator.Validate(brief, content))
        {
            byPair[(finding.From, finding.To)] = finding.Status switch
            {
                EdgeAssertionValidator.HopStatus.Confirmed => HopGraphStatus.Confirmed,
                EdgeAssertionValidator.HopStatus.Reversed => HopGraphStatus.Reversed,
                _ => HopGraphStatus.Unrecognized,
            };
        }

        return byPair;
    }

    /// <summary>
    /// Reads one line as a hop, or returns null if it is not one.
    /// </summary>
    /// <remarks>
    /// The "exactly one declared pair" rule is <see cref="HopVerdictReader"/>'s, for the reason
    /// given there: a line naming two hops cannot have its claims divided between them, and a
    /// line naming none has nothing to attach them to.
    /// </remarks>
    private static TurnHopView? TryReadHop(
        string line,
        IReadOnlyDictionary<int, string> declared,
        IReadOnlyDictionary<HopRef, HopVerdict> verdicts,
        IReadOnlyDictionary<HopRef, string> techniques,
        IReadOnlyDictionary<(string From, string To), string> graphStatus,
        int order)
    {
        var pairs = EdgeAssertionValidator.ArrowJoinedPairs(line, Arrows)
            .Where(p => declared.ContainsKey(p.From) && declared.ContainsKey(p.To))
            .Distinct()
            .Take(2)
            .ToList();

        if (pairs.Count != 1) return null;

        var (from, to) = pairs[0];
        var hop = new HopRef(declared[from], declared[to]);

        var (fromRef, toRef) = ($"N{from}", $"N{to}");
        var technique = techniques.TryGetValue(hop, out var id) ? id : null;

        // Located once and shared, so the relation and the evidence are read either side of the
        // same two occurrences. Searching for each reference independently can land on a
        // different one — Blue routinely restates a hop later in the same line ("N30 -> N1:
        // CONFIRMED, edge N30 --used-by--> N1 exists") — and then the two fields describe
        // different halves of the sentence.
        var start = line.IndexOf(fromRef, StringComparison.Ordinal);
        var end = start < 0 ? -1 : line.IndexOf(toRef, start + fromRef.Length, StringComparison.Ordinal);

        return new TurnHopView(
            Order: order,
            From: fromRef,
            To: toRef,
            FromLabel: declared[from],
            ToLabel: declared[to],
            Relation: RelationIn(line, start, end, fromRef.Length, technique),
            Technique: technique,
            Verdict: (verdicts.TryGetValue(hop, out var v) ? v : HopVerdict.Unattributed).ToString(),
            GraphStatus: graphStatus.TryGetValue((fromRef, toRef), out var status)
                ? status
                : HopGraphStatus.Unchecked,
            Evidence: EvidenceAfter(line, end, toRef.Length, technique),
            Text: line);
    }

    /// <summary>
    /// The relation word between the two node references, stripped of everything already
    /// reported as its own field.
    /// </summary>
    /// <remarks>
    /// Read positionally rather than by pattern, because the agents have written this slot four
    /// ways across live runs — <c>-&gt; can-access -&gt;</c>, <c>-&gt; technique:used-by
    /// -&gt;</c>, a bare <c>--assumes--&gt;</c>, and nothing at all. Taking the text between the
    /// endpoints and removing the parts that are separately known leaves whatever the model
    /// meant by it, or nothing.
    /// </remarks>
    private static string? RelationIn(string line, int start, int end, int fromLength, string? technique)
    {
        if (start < 0 || end <= start) return null;

        var between = line[(start + fromLength)..end];

        // The node reference may carry the agent's own inline label — N3:pkg:foo — which is not
        // part of the relation and is reported (and checked) elsewhere.
        var colon = between.IndexOf("->", StringComparison.Ordinal);
        if (colon < 0) colon = between.IndexOf('→');
        if (colon > 0 && between[..colon].Contains(':')) between = between[colon..];

        return Tidy(between, technique);
    }

    /// <summary>Whatever the agent wrote after the hop — its evidence for it, when it gave any.</summary>
    private static string? EvidenceAfter(string line, int end, int toLength, string? technique)
    {
        if (end < 0) return null;

        var tail = line[(end + toLength)..];

        // Skip past the target's own inline label, which is a restatement of the node, not
        // evidence about the hop: "-> N8:s3:customer-data-bucket, per F4" leaves ", per F4".
        var cut = tail.IndexOfAny([',', ';', '.', '|', '—', '-']);
        if (cut > 0 && tail[..cut].StartsWith(':')) tail = tail[cut..];

        return Tidy(DropEmptyFields(VerdictToken.Replace(tail, string.Empty)), technique);
    }

    /// <summary>
    /// Removes pipe-delimited fields that say there is nothing in them.
    /// </summary>
    /// <remarks>
    /// Red is instructed to write <c>none</c> when the brief grounds no ATT&amp;CK id for a hop
    /// — which is the right thing to ask for, since it distinguishes "no technique applies" from
    /// "the model skipped the field". It just must not then be read as the first word of the
    /// evidence: <c>| none | F4 grants s3:GetObject</c> is one empty field and one full one.
    /// </remarks>
    private static string DropEmptyFields(string tail) =>
        string.Join(
            " | ",
            tail.Split('|')
                .Select(field => field.Trim())
                .Where(field => field.Length > 0
                    && !EmptyFieldWords.Contains(field.TrimEnd('.', ',', ':'))));

    /// <summary>How an agent spells "this field does not apply".</summary>
    private static readonly HashSet<string> EmptyFieldWords =
        new(["none", "n/a", "na", "-", "—", "unknown"], StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Strips the tokens reported as their own fields, then the punctuation left holding them
    /// together. Returns null rather than an empty or one-character remnant.
    /// </summary>
    private static string? Tidy(string fragment, string? technique)
    {
        var text = fragment.Replace("->", " ").Replace('→', ' ');

        if (technique is not null) text = TechniqueToken.Replace(text, string.Empty);

        text = HopKeyword.Replace(text, string.Empty)
            .Trim()
            .Trim(':', ',', ';', '|', '-', '–', '—', '.', ' ')
            .Trim();

        return text.Length > 1 ? text : null;
    }

    private static int WordCount(string line) =>
        line.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length;
}
