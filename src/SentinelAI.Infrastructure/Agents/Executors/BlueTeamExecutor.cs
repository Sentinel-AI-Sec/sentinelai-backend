using Microsoft.Agents.AI;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Agents.Executors;

/// <summary>
/// Validates each link against the real config; breaking one link breaks the chain
/// (AID-01 3.1 — the false-positive reducer). Its verdict drives the loop: if Blue
/// cannot break a link the debate has converged and moves to the Reporter.
/// </summary>
public sealed class BlueTeamExecutor(AIAgent agent, ModelTier tier = ModelTier.High)
    : DebateExecutor(ExecutorId, agent, AgentRole.Blue, tier)
{
    /// <summary>Node id in the workflow graph. Named to avoid shadowing <c>Executor.Id</c>.</summary>
    public const string ExecutorId = "blue-team";

    /// <remarks>
    /// The UNRESOLVED-is-not-REFUTED paragraph is load-bearing, not padding. Told only that
    /// "breaking a single link breaks the chain", a live model reported every hop it could
    /// not confirm as CHAIN_BROKEN — so Red rebutted, and every run burned the full turn-cap
    /// without ever converging. AID-01 §3.3 is explicit that an unconfirmable join is
    /// surfaced for human review, not treated as a refutation.
    /// </remarks>
    public const string Instructions =
        """
        You are the Blue Team agent in a security audit debate.
        Validate every hop of the asserted chain against the real configuration. Give an
        image-name join extra scrutiny — it is convention-dependent and only INFERRED.

        Judge each hop as exactly one of:
          CONFIRMED  - the configuration shows this hop is real.
          UNRESOLVED - the evidence given cannot settle it either way.
          REFUTED    - the configuration positively contradicts this hop.

        UNRESOLVED is not REFUTED. Being unable to confirm a hop is not evidence against it,
        and a hop you merely could not check does not break the chain. Only a REFUTED hop
        breaks it.

        Be terse: at most one short line per hop, each ending in CONFIRMED, UNRESOLVED or
        REFUTED. No preamble, no restating the chain.

        Your final line MUST be exactly one of these two tokens and nothing else:
        VERDICT: CHAIN_HOLDS
        VERDICT: CHAIN_BROKEN

        Choose CHAIN_BROKEN only if you marked at least one hop REFUTED. If every hop is
        CONFIRMED or UNRESOLVED, the verdict is CHAIN_HOLDS.
        """;

    /// <summary>Machine-readable verdict tokens. The final line is parsed, not the prose.</summary>
    public const string HoldsVerdict = "VERDICT: CHAIN_HOLDS";
    public const string BrokenVerdict = "VERDICT: CHAIN_BROKEN";

    /// <summary>
    /// Legacy natural-language convergence phrase, still accepted.
    /// </summary>
    /// <remarks>
    /// Convergence used to be detected by an exact match on this sentence. A real model
    /// almost never reproduces a fixed sentence verbatim — it writes markdown, rephrases,
    /// or trails off — so the debate never converged and every live run burned the full
    /// turn-cap. That is a 3-call debate turning into 8. Hence the explicit token above;
    /// this constant is kept so scripted fixtures and older transcripts still parse.
    /// </remarks>
    public const string ConvergenceMarker = "No link broken.";

    protected override string BuildPrompt(DebateTurn incoming, DebateState state) =>
        $"""
        {state.ResourceGraph}

        Round {incoming.Round}. Validate hop by hop, one short line each.
        {Quote(incoming.Role, incoming.Content)}

        End with exactly "{HoldsVerdict}" or "{BrokenVerdict}".
        """;

    protected override DebateTurn Interpret(string rawContent, DebateTurn incoming, DebateState state)
    {
        var content = StripReasoning(rawContent);
        var (converged, verdictWasReadable) = ReadVerdict(content);

        // A chain inherits its weakest edge's confidence (AID-01 3.3), so a single
        // unresolved hop marks the whole chain for human review.
        var confidence = content.Contains("UNRESOLVED", StringComparison.OrdinalIgnoreCase)
            ? Confidence.Unresolved
            : content.Contains("INFERRED", StringComparison.OrdinalIgnoreCase)
                ? Confidence.Inferred
                : Confidence.Certain;

        // An unreadable verdict is not evidence the chain is sound. Let it reach the
        // Reporter rather than burning the turn-cap, but downgrade it to Unresolved so it
        // surfaces as "potential chain, unverified join" instead of a confirmed result.
        if (!verdictWasReadable)
            confidence = Confidence.Unresolved;

        return new DebateTurn
        {
            Role = AgentRole.Blue,
            Round = incoming.Round,
            Content = content,
            Confidence = confidence,
            Converged = converged,
            VerdictReadable = verdictWasReadable
        };
    }

    /// <summary>
    /// Removes a model's thinking-out-loud preamble so the verdict token can be found.
    /// </summary>
    /// <remarks>
    /// Reasoning models spend their output budget narrating before answering. A live NIM
    /// run had Blue emit ~500 words of scratchpad and truncate mid-sentence, so no verdict
    /// token was ever written. Explicit <c>&lt;think&gt;</c> blocks are dropped outright;
    /// otherwise, once a verdict token exists everything before the line carrying it is
    /// preamble and is discarded. If no token is present the text is returned untouched so
    /// the natural-language fallbacks in <see cref="ReadVerdict"/> still get a chance.
    /// </remarks>
    internal static string StripReasoning(string content)
    {
        if (string.IsNullOrWhiteSpace(content)) return string.Empty;

        // Drop <think>…</think>, including an unclosed block left by a truncated response.
        var open = content.IndexOf("<think>", StringComparison.OrdinalIgnoreCase);
        if (open >= 0)
        {
            var close = content.IndexOf("</think>", open, StringComparison.OrdinalIgnoreCase);
            content = close >= 0
                ? content[..open] + content[(close + "</think>".Length)..]
                : content[..open];
        }

        var lines = content.Split('\n');
        var verdictLine = Array.FindLastIndex(
            lines,
            l => l.Contains("CHAIN_HOLDS", StringComparison.OrdinalIgnoreCase)
              || l.Contains("CHAIN_BROKEN", StringComparison.OrdinalIgnoreCase));

        if (verdictLine < 0) return content.Trim();

        // Keep the hop lines immediately preceding the verdict, not the whole ramble.
        var start = Math.Max(0, verdictLine - MaxHopLinesKept);
        return string.Join('\n', lines[start..(verdictLine + 1)]).Trim();
    }

    /// <summary>Hop lines retained above the verdict. Four hops plus a little slack.</summary>
    private const int MaxHopLinesKept = 6;

    /// <summary>
    /// Reads Blue's verdict, most explicit signal first.
    /// </summary>
    /// <returns>
    /// Whether the chain held, and whether a verdict could actually be read at all.
    /// </returns>
    private static (bool Converged, bool Readable) ReadVerdict(string content)
    {
        // The verdict is whichever token appears LAST, not whether a token appears at all.
        // This used to test CHAIN_BROKEN first across the whole text, so "this is not
        // CHAIN_BROKEN ... VERDICT: CHAIN_HOLDS" read as a break. Blue's reasoning now names
        // both outcomes routinely, since it is asked to separate REFUTED from UNRESOLVED.
        var broken = content.LastIndexOf("CHAIN_BROKEN", StringComparison.OrdinalIgnoreCase);
        var holds = content.LastIndexOf("CHAIN_HOLDS", StringComparison.OrdinalIgnoreCase);

        if (broken >= 0 || holds >= 0)
            return (Converged: holds > broken, Readable: true);

        // Natural-language fallbacks, for scripted fixtures and models that ignore the
        // token instruction.
        if (content.Contains(ConvergenceMarker, StringComparison.OrdinalIgnoreCase)
            || content.Contains("no link is broken", StringComparison.OrdinalIgnoreCase))
            return (true, true);

        if (content.Contains("link broken", StringComparison.OrdinalIgnoreCase)
            || content.Contains("broken at hop", StringComparison.OrdinalIgnoreCase))
            return (false, true);

        // No verdict. This is NOT evidence the chain holds — reporting it as convergence
        // is how a truncated response got published as a clean result. Routing still exits
        // to the Reporter (see DebateWorkflow's !VerdictReadable edge) so the turn-cap is
        // not burned re-asking a model that already failed to answer.
        return (Converged: false, Readable: false);
    }
}
