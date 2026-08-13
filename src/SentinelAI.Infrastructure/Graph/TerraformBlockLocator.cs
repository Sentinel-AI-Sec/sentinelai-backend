using System.Text.RegularExpressions;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// A line-addressed index of the <c>resource</c> blocks in one Terraform file, so a scanner
/// finding reported at <c>infra/iam.tf:25</c> can be traced back to the block that line is
/// inside.
/// </summary>
/// <remarks>
/// Separate from <see cref="TerraformHclParser"/> rather than an extension of it: that parser
/// concatenates every file into one buffer, which is right for reference resolution (Terraform
/// ignores file boundaries within a directory) and fatal here, since a line number only means
/// something relative to the file it was reported against.
/// </remarks>
internal static partial class TerraformBlockLocator
{
    [GeneratedRegex("""resource\s+"([A-Za-z0-9_]+)"\s+"([A-Za-z0-9_]+)"\s*\{""", RegexOptions.CultureInvariant)]
    private static partial Regex ResourceBlockHeader();

    /// <summary>Indexes one file's resource blocks, in declaration order.</summary>
    public static IReadOnlyList<TerraformBlock> Index(string hclText)
    {
        var blocks = new List<TerraformBlock>();
        if (string.IsNullOrEmpty(hclText)) return blocks;

        // One pass over the text recording where each line starts, so a character offset
        // becomes a line number by binary search instead of re-counting newlines per block.
        var lineStarts = LineStarts(hclText);

        foreach (Match header in ResourceBlockHeader().Matches(hclText))
        {
            var bodyStart = header.Index + header.Length;
            var bodyEnd = FindMatchingBrace(hclText, bodyStart);
            if (bodyEnd < 0) continue;

            blocks.Add(new TerraformBlock(
                ResourceType: header.Groups[1].Value,
                ResourceName: header.Groups[2].Value,
                StartLine: LineOf(lineStarts, header.Index),
                EndLine: LineOf(lineStarts, bodyEnd),
                Body: hclText[bodyStart..bodyEnd]));
        }

        return blocks;
    }

    /// <summary>
    /// The block containing <paramref name="line"/> (1-based), or null when the line falls
    /// between blocks — a comment, a <c>provider</c> stanza, a blank line.
    /// </summary>
    /// <remarks>
    /// The innermost containing block wins, so a nested <c>ingress</c>/<c>statement</c> stanza
    /// resolves to its enclosing resource rather than to whichever block was declared first.
    /// Top-level resource blocks do not nest in practice; this just keeps the rule stated
    /// instead of relying on that.
    /// </remarks>
    public static TerraformBlock? BlockAt(IReadOnlyList<TerraformBlock> blocks, int line)
    {
        TerraformBlock? innermost = null;

        foreach (var block in blocks)
        {
            if (line < block.StartLine || line > block.EndLine) continue;
            if (innermost is null || block.StartLine > innermost.StartLine) innermost = block;
        }

        return innermost;
    }

    private static int[] LineStarts(string text)
    {
        var starts = new List<int> { 0 };
        for (var i = 0; i < text.Length; i++)
            if (text[i] == '\n') starts.Add(i + 1);

        return [.. starts];
    }

    /// <summary>1-based line number of a character offset.</summary>
    private static int LineOf(int[] lineStarts, int offset)
    {
        var index = Array.BinarySearch(lineStarts, offset);
        return index >= 0 ? index + 1 : ~index;
    }

    /// <summary>Mirrors <c>TerraformHclParser.FindMatchingBrace</c> — see
    /// <see cref="TerraformIamPolicyParser"/>'s doc remarks for why this is a separate copy.</summary>
    private static int FindMatchingBrace(string text, int bodyStart)
    {
        var depth = 1;
        for (var i = bodyStart; i < text.Length; i++)
        {
            if (text[i] == '{') depth++;
            else if (text[i] == '}' && --depth == 0) return i;
        }

        return -1;
    }
}

/// <summary>One <c>resource</c> block and the line span it occupies in its own file.</summary>
/// <param name="StartLine">Line of the <c>resource "..." "..." {</c> header, 1-based.</param>
/// <param name="EndLine">Line of the closing brace, 1-based and inclusive.</param>
internal sealed record TerraformBlock(
    string ResourceType, string ResourceName, int StartLine, int EndLine, string Body)
{
    public string Address => $"{ResourceType}.{ResourceName}";
}
