namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-17 step 1: turns <c>terraform graph</c> DOT text into a raw resource graph — literal
/// Terraform addresses (<c>aws_iam_role.order_task_role</c>), in Terraform's own edge
/// direction. Deliberately narrow: no canonical <c>NodeId</c>, no attack-direction reasoning,
/// no notion of which resource types matter to us. That happens later, in
/// <see cref="AttackDirectionOrienter"/> (step 2) and <c>TerraformInfraSpineReader</c> (step 3).
/// </summary>
/// <remarks>
/// Line-scanning rather than a real DOT grammar, on purpose: <c>terraform graph</c> output is a
/// narrow, well-known subset of DOT (quoted node names, plain <c>-&gt;</c> edges, a handful of
/// bracketed attributes we never need), and hand-rolling the handful of patterns it actually
/// uses avoids taking on a general graph-description-language dependency for that subset. Every
/// address is re-derived from its own line's text rather than assumed to match a fixed layout,
/// so quoting/whitespace drift between Terraform versions is tolerated as long as node names
/// stay quoted (they always have been across every Terraform version this reads).
/// </remarks>
internal static class TerraformDotParser
{
    private static readonly string[] OperationSuffixes =
        [" (expand)", " (close)", " (destroy deposed)", " (destroy)", " (create)", " (update)"];

    public static TerraformRawGraph Parse(string? dotText)
    {
        var nodesByAddress = new Dictionary<string, TerraformRawNode>(StringComparer.Ordinal);
        var edgeAddresses = new HashSet<(string From, string To)>();

        if (string.IsNullOrWhiteSpace(dotText))
            return new TerraformRawGraph([], []);

        foreach (var rawLine in dotText.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith("//", StringComparison.Ordinal) || line.StartsWith('#'))
                continue;

            line = line.TrimEnd(';', ' ');

            // Only statements that name a node start with a quote — graph/node/edge default
            // attributes (`rankdir = "RL";`, `node [shape = rect];`) and the `digraph G {`
            // header never do, so this is enough to skip them without parsing DOT's full
            // attribute-list grammar.
            if (!line.StartsWith('"'))
                continue;

            var arrow = line.IndexOf("->", StringComparison.Ordinal);
            if (arrow >= 0)
            {
                var fromRaw = ExtractFirstQuoted(line.AsSpan(0, arrow));
                var toRaw = ExtractFirstQuoted(line.AsSpan(arrow + 2));

                if (fromRaw is null || toRaw is null) continue;
                if (!TryParseAddress(fromRaw, out var fromNode) || !TryParseAddress(toRaw, out var toNode)) continue;

                // Both endpoints resolved to a real resource — keep the node declarations
                // (a `-&gt;` line may be the only place one of these addresses appears) and
                // the edge between them. Either side failing (a provider, a data source, some
                // other non-resource noise) drops the whole edge, per the ticket: an edge is
                // only as real as its weakest endpoint.
                nodesByAddress[fromNode.Address] = fromNode;
                nodesByAddress[toNode.Address] = toNode;
                edgeAddresses.Add((fromNode.Address, toNode.Address));
                continue;
            }

            var addressRaw = ExtractFirstQuoted(line.AsSpan());
            if (addressRaw is not null && TryParseAddress(addressRaw, out var node))
                nodesByAddress[node.Address] = node;
        }

        var edges = edgeAddresses.Select(e => new TerraformRawEdge(e.From, e.To)).ToList();
        return new TerraformRawGraph([.. nodesByAddress.Values], edges);
    }

    /// <summary>
    /// The text inside the first quoted token, with DOT's <c>\"</c> escaping undone. Null if
    /// the span has no quoted token at all.
    /// </summary>
    private static string? ExtractFirstQuoted(ReadOnlySpan<char> s)
    {
        var start = s.IndexOf('"');
        if (start < 0) return null;

        var sb = new System.Text.StringBuilder();
        var i = start + 1;
        while (i < s.Length)
        {
            var c = s[i];
            if (c == '\\' && i + 1 < s.Length)
            {
                sb.Append(s[i + 1]);
                i += 2;
                continue;
            }
            if (c == '"') break;
            sb.Append(c);
            i++;
        }

        return sb.ToString();
    }

    /// <summary>
    /// Parses a quoted DOT node name into a resource address, or reports it as noise.
    /// Handles the <c>[root] </c> prefix and <c>(expand)</c>/<c>(close)</c>/... suffixes older
    /// and newer Terraform versions wrap resource addresses in, module-qualified addresses
    /// (<c>module.storage.aws_s3_bucket.x</c>, including nested modules), and drops provider
    /// nodes (<c>provider["registry.terraform.io/hashicorp/aws"]</c>) and anything else that
    /// isn't shaped like <c>[module.&lt;name&gt;.]*&lt;type&gt;.&lt;name&gt;</c> — which
    /// includes data sources (<c>data.aws_caller_identity.current</c>): not a managed resource,
    /// so out of scope for a graph about what attackers can reach and change.
    /// </summary>
    private static bool TryParseAddress(string raw, out TerraformRawNode node)
    {
        node = null!;
        var s = raw.Trim();
        if (s.Length == 0) return false;

        if (s.StartsWith("[root] ", StringComparison.Ordinal))
            s = s["[root] ".Length..].Trim();

        foreach (var suffix in OperationSuffixes)
        {
            if (s.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                s = s[..^suffix.Length].Trim();
                break;
            }
        }

        if (s.StartsWith("provider[", StringComparison.OrdinalIgnoreCase) ||
            s.StartsWith("provider.", StringComparison.OrdinalIgnoreCase))
            return false;

        var parts = s.Split('.');
        if (parts.Length < 2) return false;

        var resourceType = parts[^2];
        var resourceName = parts[^1];
        if (resourceType.Length == 0 || resourceName.Length == 0) return false;

        var modulePrefix = parts[..^2];
        if (modulePrefix.Length % 2 != 0) return false;
        for (var i = 0; i < modulePrefix.Length; i += 2)
        {
            if (!string.Equals(modulePrefix[i], "module", StringComparison.OrdinalIgnoreCase))
                return false;
        }

        var modulePath = string.Join('.', modulePrefix.Where((_, i) => i % 2 == 1));

        node = new TerraformRawNode(s, modulePath, resourceType, resourceName);
        return true;
    }
}

/// <summary>
/// A resource address as Terraform expressed it — not yet a canonical NodeId. See
/// <c>TerraformInfraSpineReader</c> for where that happens.
/// </summary>
/// <param name="Address">The normalized address (root-prefix/operation-suffix stripped), used
/// as the stable join key between node declarations and edge endpoints.</param>
/// <param name="ModulePath">Dot-joined module names, e.g. <c>storage</c> or <c>storage.inner</c>
/// for a nested module; empty at the root module.</param>
internal sealed record TerraformRawNode(string Address, string ModulePath, string ResourceType, string ResourceName)
{
    /// <summary>
    /// The identifier a canonical NodeId should be built from — module-qualified so that two
    /// modules' same-named resources (<c>module.a.aws_s3_bucket.x</c> and
    /// <c>module.b.aws_s3_bucket.x</c>) don't collide on one node key.
    /// </summary>
    public string Identifier => ModulePath.Length == 0 ? ResourceName : $"{ModulePath}.{ResourceName}";
}

/// <summary>An edge exactly as Terraform drew it: <see cref="FromAddress"/> depends on <see cref="ToAddress"/>.</summary>
internal sealed record TerraformRawEdge(string FromAddress, string ToAddress);

internal sealed record TerraformRawGraph(IReadOnlyList<TerraformRawNode> Nodes, IReadOnlyList<TerraformRawEdge> Edges);
