using System.Text;
using System.Text.RegularExpressions;

namespace SentinelAI.Application.Debate;

/// <summary>
/// Normalises a model's raw turn text into the plain, line-oriented prose the rest of the
/// system assumes it already is.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> Every consumer of a turn — the transcript panel, the summary on the
/// report, <see cref="HopVerdictReader"/>, <see cref="EdgeAssertionValidator"/> — was written
/// against the text the instructions ask for: short lines, one hop each, no decoration. What
/// providers actually return is that text wrapped in whatever house style the model was tuned
/// with: a <c>&lt;think&gt;</c> scratchpad, a <c>### Chain</c> heading, bullets, and
/// <c>**bold**</c> around the very tokens the readers match on. None of that carries meaning
/// here, and all of it reaches the screen verbatim, because the turn is rendered as-is.
/// </para>
/// <para>
/// <b>What it deliberately does not do.</b> It removes decoration; it never rewrites, reorders,
/// summarises or re-cases a word. Case in particular is load-bearing downstream — Blue's
/// vocabulary is matched case-sensitively precisely so that lower-case prose ("not fully
/// confirmed") cannot pass as a verdict — so nothing here touches it. A line this cannot
/// improve is returned unchanged rather than dropped: text nobody can parse is still text a
/// human can read, and hiding it is worse than showing it plainly.
/// </para>
/// </remarks>
public static class TranscriptText
{
    /// <summary>A markdown ATX heading marker at the start of a line: <c>### Chain</c>.</summary>
    private static readonly Regex Heading = new(@"^\s{0,3}#{1,6}\s+", RegexOptions.Compiled);

    /// <summary>
    /// A leading list marker — <c>- </c>, <c>* </c>, <c>• </c>, <c>1. </c>, <c>2) </c>.
    /// </summary>
    /// <remarks>
    /// The number is dropped with the marker rather than kept as prose. Hop lines carry their
    /// own ordering (they are read in the order they appear), and a rendered "1. 1. hop" is
    /// what keeping both looks like.
    /// </remarks>
    private static readonly Regex ListMarker =
        new(@"^\s{0,6}(?:[-*+•–]|\d{1,2}[.)])\s+", RegexOptions.Compiled);

    /// <summary>Markdown emphasis and code fencing around a run of text.</summary>
    /// <remarks>
    /// Matched as paired delimiters with content between them, so a lone asterisk in
    /// <c>s3:bucket/*</c> or an underscore inside <c>api_task_role</c> survives — those are
    /// parts of resource names, and mangling one is how a node label stops matching the graph.
    /// </remarks>
    private static readonly Regex Emphasis = new(
        @"(?<open>\*\*|__|\*|`)(?<text>[^\s*_`](?:[^*_`]*[^\s*_`])?)\k<open>",
        RegexOptions.Compiled);

    /// <summary>A horizontal rule, which is decoration with no textual content at all.</summary>
    private static readonly Regex HorizontalRule = new(@"^\s*(?:[-*_]\s*){3,}$", RegexOptions.Compiled);

    /// <summary>Three or more newlines, which render as a gap nobody wrote deliberately.</summary>
    private static readonly Regex ExcessBlankLines = new(@"\n{3,}", RegexOptions.Compiled);

    /// <summary>
    /// Strips a model's thinking-out-loud block, then the markdown it wrapped its answer in.
    /// </summary>
    /// <returns>
    /// The cleaned text, trimmed. Empty input — and input that was nothing but a scratchpad —
    /// returns <see cref="string.Empty"/>.
    /// </returns>
    public static string Clean(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return string.Empty;

        var text = StripThinking(raw).Replace("\r\n", "\n").Replace('\r', '\n');
        var cleaned = new StringBuilder(text.Length);

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.Trim();

            if (HorizontalRule.IsMatch(line))
            {
                cleaned.Append('\n');
                continue;
            }

            line = Heading.Replace(line, string.Empty);
            line = ListMarker.Replace(line, string.Empty);
            line = Emphasis.Replace(line, "${text}");

            cleaned.Append(line.TrimEnd()).Append('\n');
        }

        return ExcessBlankLines.Replace(cleaned.ToString(), "\n\n").Trim();
    }

    /// <summary>
    /// Removes a <c>&lt;think&gt;…&lt;/think&gt;</c> scratchpad, including an unclosed one.
    /// </summary>
    /// <remarks>
    /// An unclosed block means the response ran out of budget while still narrating, so
    /// everything from the tag onward is scratchpad and the turn has no answer in it. Keeping
    /// the prefix and dropping the rest is the honest reading: what survives is whatever the
    /// model had committed to before it started thinking aloud, which is usually nothing.
    /// <para>
    /// Lifted out of <c>BlueTeamExecutor.StripReasoning</c>, which needed it first and for a
    /// sharper reason — a scratchpad that buries the verdict token costs a converged debate —
    /// but all four agents are served by the same providers and all four leak the same block.
    /// </para>
    /// </remarks>
    public static string StripThinking(string content)
    {
        if (string.IsNullOrEmpty(content)) return string.Empty;

        var open = content.IndexOf("<think>", StringComparison.OrdinalIgnoreCase);
        if (open < 0) return content;

        var close = content.IndexOf("</think>", open, StringComparison.OrdinalIgnoreCase);
        return close >= 0
            ? content[..open] + content[(close + "</think>".Length)..]
            : content[..open];
    }
}
