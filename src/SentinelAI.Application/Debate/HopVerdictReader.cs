using System.Text.RegularExpressions;
using SentinelAI.Domain.Enums;

namespace SentinelAI.Application.Debate;

/// <summary>One hop, named the only way the transcript can name one: by its two endpoints.</summary>
/// <remarks>
/// Node <em>keys</em>, not the <c>N&lt;n&gt;</c> labels the agents write. The labels are
/// positional in one rendering of one brief; the keys are canonical and are what
/// <c>graph_nodes</c> actually stores, so this is the form a caller can join on.
/// </remarks>
public readonly record struct HopRef(string FromNodeKey, string ToNodeKey);

/// <summary>
/// Reads the two per-hop facts that exist only in the debate transcript — Blue's verdict on a
/// hop, and the ATT&amp;CK technique Red named for it — out of Red's and Blue's free text
/// (audit 42-A).
/// </summary>
/// <remarks>
/// <para>
/// <b>What made this recoverable, and what still is not.</b> Blue's instructions already fix a
/// closed vocabulary and a shape: "at most one short line per hop, each ending in CONFIRMED,
/// UNRESOLVED or REFUTED", and live turns name the hop's two nodes on that same line
/// (<c>N30 -&gt; used-by -&gt; N1: CONFIRMED, edge N30 --used-by--&gt; N1 exists.</c>). That is
/// a verdict token and an anchor on one line, which is enough. Red's are weaker: it is asked for
/// "node -&gt; technique -&gt; evidence", and the technique slot in live turns has held the
/// graph's own relation word (<c>technique:used-by</c>), not an ATT&amp;CK id. So Red's
/// instructions were amended to ask for the id explicitly, and even then an id is only kept when
/// the brief itself names it — see <see cref="ReadTechniques"/>.
/// </para>
/// <para>
/// <b>Why this is not the brittle regex the ticket warned about.</b> Nothing here infers,
/// defaults, or fills a gap. Every rule below turns doubt into <em>no answer</em> rather than
/// into a plausible one:
/// </para>
/// <list type="bullet">
///   <item>A hop is anchored by its two node references with an arrow between them — the same
///   rule <see cref="EdgeAssertionValidator"/> has always used, sharing its implementation, so
///   there is one idea of what a hop line is rather than two.</item>
///   <item>A line must carry exactly one distinct verdict token and exactly one distinct hop.
///   Two of either and the line is dropped: "hops 2 and 3 CONFIRMED" cannot be split, and
///   neither can "UNRESOLVED, certainly not REFUTED".</item>
///   <item>A verdict token with a negation in front of it — "NOT CONFIRMED" — drops the line.
///   Reading that as a confirmation is the single worst failure this parser could have.</item>
///   <item>Two lines disagreeing about the same hop retract it entirely; the contradiction is
///   not resolved by taking the first, the last, or the worst.</item>
///   <item>Tokens are matched case-sensitively, because the instructions mandate them in
///   upper case and lower-case prose is where a model hedges: "not fully confirmed" is
///   discussion, "CONFIRMED" is a verdict.</item>
/// </list>
/// <para>
/// The caller therefore never receives a guess. A hop this class says nothing about stays
/// <see cref="HopVerdict.Unattributed"/> — visibly undetermined, never
/// <see cref="HopVerdict.Refuted"/> and never a silent <c>false</c>.
/// </para>
/// </remarks>
public static class HopVerdictReader
{
    /// <summary>
    /// Blue's three-token vocabulary, spelled exactly as <c>BlueTeamExecutor.Instructions</c>
    /// mandates it.
    /// </summary>
    /// <remarks>
    /// Case-sensitive and word-bounded. The bound is what keeps <c>UNCONFIRMED</c> from reading
    /// as <c>CONFIRMED</c>; the case is what keeps ordinary prose out.
    /// </remarks>
    private static readonly Regex VerdictToken =
        new(@"\b(?<verdict>CONFIRMED|UNRESOLVED|REFUTED)\b", RegexOptions.Compiled);

    /// <summary>
    /// An ATT&amp;CK technique or sub-technique id: <c>T1078</c>, <c>T1078.004</c>.
    /// </summary>
    /// <remarks>
    /// Four digits and an optional three-digit sub-technique is MITRE's own shape. Anchored on
    /// word boundaries so a CVE year, a CWE number or a task name cannot masquerade as one.
    /// </remarks>
    private static readonly Regex TechniqueToken =
        new(@"\bT(?<technique>\d{4}(?:\.\d{3})?)\b", RegexOptions.Compiled);

    /// <summary>
    /// A negation immediately before a verdict token, in either agent's usual phrasings.
    /// </summary>
    /// <remarks>
    /// Anchored at the end of the text preceding the token, so it only fires on the words
    /// actually attached to it. "This hop is NOT CONFIRMED" and "we cannot say CONFIRMED" are
    /// both caught; "no other hop was checked ... N1 -&gt; N2 CONFIRMED" is not, because the
    /// negation is not adjacent.
    /// <para>
    /// The window of up to two intervening words is what makes the second of those work:
    /// "cannot <em>say</em> CONFIRMED" puts a verb between the negation and the token, and
    /// English keeps doing that ("could not <em>fully</em> confirm"). It stays deliberately
    /// short, because every word of slack is another chance to capture a negation belonging to
    /// an earlier clause. Erring wide is safe in the only direction that matters: an over-eager
    /// match returns no verdict, so the hop lands on <see cref="HopVerdict.Unattributed"/> —
    /// "Blue said nothing this hop can be held to" — never on a verdict Blue did not give.
    /// </para>
    /// </remarks>
    private static readonly Regex NegationBeforeVerdict = new(
        @"\b(?:not|no|never|cannot|can't|couldn't|unable\s+to|isn't|wasn't|aren't|fails?\s+to)\b"
        + @"(?:\s+[\w'\u2019-]+){0,2}\s*$",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// The arrow spellings a hop line may use. Wider than
    /// <see cref="EdgeAssertionValidator.AsciiArrow"/> on purpose: the stub resource graph writes
    /// its edges with <c>→</c> and the agents mirror whatever the brief taught them, so a turn
    /// answering a stub brief would otherwise anchor nothing at all. Widening it here is safe in
    /// a way widening it there is not — a pair this class cannot match to a real persisted hop
    /// is simply discarded, whereas the validator's pairs decide whether a chain is capped.
    /// </summary>
    private static readonly string[] Arrows = ["->", "→"];

    /// <summary>
    /// Blue's per-hop verdicts, keyed by the hop's two node keys.
    /// </summary>
    /// <remarks>
    /// A hop absent from the result is a hop Blue said nothing attributable about. That is
    /// deliberately indistinguishable, here, from a hop it never mentioned — both mean "no
    /// verdict", and the caller records both as <see cref="HopVerdict.Unattributed"/>.
    /// </remarks>
    public static IReadOnlyDictionary<HopRef, HopVerdict> ReadVerdicts(string briefContext, string? blueText) =>
        ReadPerHop<HopVerdict>(
            briefContext,
            blueText,
            line =>
            {
                var verdicts = new HashSet<HopVerdict>();

                foreach (Match m in VerdictToken.Matches(line))
                {
                    // A negated token does not vote for the opposite verdict — it makes the whole
                    // line unreadable, which is the answer with no fabrication in it.
                    if (NegationBeforeVerdict.IsMatch(line[..m.Index])) return null;

                    verdicts.Add(m.Groups["verdict"].Value switch
                    {
                        "CONFIRMED" => HopVerdict.Confirmed,
                        "UNRESOLVED" => HopVerdict.Unresolved,
                        _ => HopVerdict.Refuted,
                    });
                }

                return verdicts.Count == 1 ? verdicts.Single() : null;
            });

    /// <summary>
    /// The ATT&amp;CK technique id Red named for each hop, keyed by the hop's two node keys.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>An id is kept only if the brief already contains it.</b> The knowledge section of the
    /// brief is retrieved from the corpus and names techniques outright ("ATT&amp;CK T1078 —
    /// Valid Accounts"); an id Red produces that appears nowhere in the text it was given came
    /// from the model's own memory, and there is nothing in this system that can check it. This
    /// is the same stance <see cref="EdgeAssertionValidator"/> takes on edges: ground truth is
    /// the brief the model actually read, and an unsupported claim is dropped rather than
    /// published.
    /// </para>
    /// <para>
    /// A sub-technique whose parent — and only its parent — is in the brief does not count as
    /// grounded. <c>T1078.004</c> asserts "Cloud Accounts" specifically where the corpus said
    /// only "Valid Accounts", and precision the evidence does not support is the failure mode
    /// this whole audit is about.
    /// </para>
    /// </remarks>
    public static IReadOnlyDictionary<HopRef, string> ReadTechniques(string briefContext, string? redText)
    {
        var grounded = TechniqueIdsIn(briefContext);
        if (grounded.Count == 0) return new Dictionary<HopRef, string>();

        // Wrapped rather than a plain string so this shares the one implementation of the line
        // walk below, whose value type is constrained to a struct for the "did it say anything?"
        // null check to be unambiguous.
        return ReadPerHop<Grounded>(
            briefContext,
            redText,
            line =>
            {
                var named = TechniqueIdsIn(line);
                named.IntersectWith(grounded);

                // Two techniques on one hop line is a claim we cannot split between them, and
                // one nobody asked for: Red is told to name the technique, singular.
                return named.Count == 1 ? new Grounded(named.Single()) : null;
            })
            .ToDictionary(kv => kv.Key, kv => kv.Value.TechniqueId);
    }

    /// <summary>One grounded ATT&amp;CK id, in the struct shape <see cref="ReadPerHop"/> needs.</summary>
    private readonly record struct Grounded(string TechniqueId);

    /// <summary>Every ATT&amp;CK id in a piece of text, normalised to <c>T####[.###]</c>.</summary>
    private static HashSet<string> TechniqueIdsIn(string? text)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(text)) return ids;

        foreach (Match m in TechniqueToken.Matches(text))
            ids.Add($"T{m.Groups["technique"].Value}");

        return ids;
    }

    /// <summary>
    /// The shared line walk: one line, one hop, one value — or nothing.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Both callers need the same three things and the same refusals, so they share the walk and
    /// supply only "what is this line claiming?". <paramref name="valueOf"/> returning
    /// <c>null</c> means the line said nothing usable, and is the normal outcome for a preamble
    /// line, a restatement, or a hedge.
    /// </para>
    /// <para>
    /// <b>Exactly one hop per line.</b> A line naming two hops cannot have one verdict divided
    /// between them, and a line naming none has nothing to attach a verdict to. Both are dropped
    /// rather than attached to the nearest candidate — "nearest" is a guess, and a guess written
    /// into a hop row is indistinguishable from a fact to everyone downstream.
    /// </para>
    /// <para>
    /// <b>Contradictions retract.</b> If two lines claim different things about one hop, the hop
    /// is removed and blocked from being re-added. Preferring the first, the last, or the most
    /// pessimistic would each be a policy invented here about text neither agent meant to be
    /// read that way.
    /// </para>
    /// </remarks>
    private static IReadOnlyDictionary<HopRef, T> ReadPerHop<T>(
        string briefContext, string? agentText, Func<string, T?> valueOf) where T : struct
    {
        var found = new Dictionary<HopRef, T>();
        if (string.IsNullOrWhiteSpace(briefContext) || string.IsNullOrWhiteSpace(agentText))
            return found;

        var declared = EdgeAssertionValidator.DeclaredNodeKeys(briefContext);
        if (declared.Count == 0) return found;

        var contradicted = new HashSet<HopRef>();

        foreach (var line in agentText.Split('\n'))
        {
            var hops = EdgeAssertionValidator.ArrowJoinedPairs(line, Arrows)
                .Where(p => declared.ContainsKey(p.From) && declared.ContainsKey(p.To))
                .Select(p => new HopRef(declared[p.From], declared[p.To]))
                .Distinct()
                .Take(2)
                .ToList();

            if (hops.Count != 1) continue;

            var hop = hops[0];
            if (contradicted.Contains(hop)) continue;

            if (valueOf(line) is not { } value) continue;

            if (found.TryGetValue(hop, out var already))
            {
                if (!EqualityComparer<T>.Default.Equals(already, value))
                {
                    found.Remove(hop);
                    contradicted.Add(hop);
                }

                continue;
            }

            found[hop] = value;
        }

        return found;
    }
}
