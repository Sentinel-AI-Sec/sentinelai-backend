using System.Text.RegularExpressions;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-18 part B, step 1: reads Terraform's three IAM-policy-attachment shapes out of raw
/// <c>.tf</c> source and turns each into the role→resource grants it expresses. HCL-source-only
/// on purpose — the <c>terraform graph</c> DOT output carries resource structure, never policy
/// statement text, so unlike <see cref="TerraformInfraSpineReader"/> there is no DOT path for
/// this seam to prefer.
/// </summary>
/// <remarks>
/// <para>
/// Covers, per the ticket, all three patterns Terraform allows for granting a role access:
/// </para>
/// <list type="bullet">
/// <item>Inline: a <c>inline_policy { policy = jsonencode({...}) }</c> block nested inside
/// <c>aws_iam_role</c> itself.</item>
/// <item>Standalone: a separate <c>aws_iam_role_policy</c> resource, joined back to its role by
/// a <c>role = aws_iam_role.&lt;name&gt;...</c> reference in its own body.</item>
/// <item>Managed attachment: <c>aws_iam_role_policy_attachment</c>, which names a
/// <c>policy_arn</c> rather than embedding statement JSON — see
/// <see cref="InferServiceFromManagedPolicyArn"/> for how (and how approximately) this reader
/// turns that into a grant.</item>
/// </list>
/// <para>
/// Block/body extraction (<see cref="FindMatchingBrace"/>, the resource-header regex) is
/// deliberately shaped like <c>TerraformHclParser</c>'s own — brace-counting over a hand-written
/// grammar, for the same reason that class gives: <c>terraform graph</c>/HCL's actual shape here
/// is a narrow, well-known pattern, not something worth a full HCL parser dependency for. It is
/// a separate copy rather than a shared call into <c>TerraformHclParser</c> because that class
/// returns declared addresses and cross-references only, never a block's raw body text — which
/// is exactly what statement JSON (Effect/Action/Resource) lives inside, and SEC-17's file is
/// frozen for this ticket (see this project's task brief: SEC-17's own code is not to be
/// modified).
/// </para>
/// </remarks>
internal static partial class TerraformIamPolicyParser
{
    [GeneratedRegex("""resource\s+"([A-Za-z0-9_]+)"\s+"([A-Za-z0-9_]+)"\s*\{""", RegexOptions.CultureInvariant)]
    private static partial Regex ResourceBlockHeader();

    [GeneratedRegex(@"aws_iam_role\.([A-Za-z_][A-Za-z0-9_]*)", RegexOptions.CultureInvariant)]
    private static partial Regex RoleReference();

    [GeneratedRegex(@"([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)", RegexOptions.CultureInvariant)]
    private static partial Regex TypeDotNameReference();

    [GeneratedRegex(""""Effect\s*=\s*"([A-Za-z]+)"""", RegexOptions.CultureInvariant)]
    private static partial Regex EffectField();

    [GeneratedRegex("""Action\s*=\s*("[^"]*"|\[[^\]]*\])""", RegexOptions.CultureInvariant)]
    private static partial Regex ActionField();

    [GeneratedRegex("""Resource\s*=\s*("[^"]*"|\[[^\]]*\]|[^,\r\n}]+)""", RegexOptions.CultureInvariant)]
    private static partial Regex ResourceField();

    [GeneratedRegex(""""policy_arn\s*=\s*"([^"]*)"""", RegexOptions.CultureInvariant)]
    private static partial Regex PolicyArnField();

    [GeneratedRegex(@"""([a-z0-9]+):", RegexOptions.CultureInvariant)]
    private static partial Regex ActionServicePrefix();

    /// <summary>Approximate managed-policy-name → Terraform-resource-type-prefix map, used only
    /// to narrow a managed attachment's widened targets to the service it plausibly names. Not
    /// exhaustive — AWS ships hundreds of managed policies — so an unrecognized name falls back
    /// to widening across every known <c>Resource</c>-typed node rather than guessing wrong.</summary>
    private static readonly Dictionary<string, string> ManagedPolicyServiceHints = new(StringComparer.OrdinalIgnoreCase)
    {
        ["s3"] = "s3",
    };

    public static IReadOnlyList<RoleResourceGrant> ParseGrants(IReadOnlyDictionary<string, string> hclFiles)
    {
        if (hclFiles.Count == 0) return [];

        var combined = string.Join('\n', hclFiles.Values);
        var grants = new List<RoleResourceGrant>();

        foreach (Match header in ResourceBlockHeader().Matches(combined))
        {
            var resourceType = header.Groups[1].Value;
            var bodyStart = header.Index + header.Length;
            var bodyEnd = FindMatchingBrace(combined, bodyStart);
            if (bodyEnd < 0) continue;
            var body = combined[bodyStart..bodyEnd];

            switch (resourceType)
            {
                case "aws_iam_role":
                    // The role's own identifier is its resource NAME, not a reference — a role
                    // granting itself access via its own inline policy has no "role = ..."
                    // attribute to read.
                    var roleName = header.Groups[2].Value;
                    foreach (var inlineBody in ExtractNestedBlocks(body, "inline_policy"))
                    {
                        var targets = ParseTargets(inlineBody);
                        if (targets.Count > 0) grants.Add(new RoleResourceGrant(roleName, targets));
                    }
                    break;

                case "aws_iam_role_policy":
                    var referencedRole = RoleReference().Match(body);
                    if (referencedRole.Success)
                    {
                        var targets = ParseTargets(body);
                        if (targets.Count > 0) grants.Add(new RoleResourceGrant(referencedRole.Groups[1].Value, targets));
                    }
                    break;

                case "aws_iam_role_policy_attachment":
                    var attachedRole = RoleReference().Match(body);
                    var arn = PolicyArnField().Match(body);
                    if (attachedRole.Success && arn.Success)
                    {
                        var servicePrefix = InferServiceFromManagedPolicyArn(arn.Groups[1].Value);
                        grants.Add(new RoleResourceGrant(
                            attachedRole.Groups[1].Value,
                            [new GrantTarget(IsWildcard: true, ResourceAddress: null, ServicePrefix: servicePrefix)]));
                    }
                    break;
            }
        }

        return grants;
    }

    /// <summary>
    /// Every grant target a <c>Statement = [ {...}, {...} ]</c> array expresses. Only
    /// <c>"Allow"</c> statements grant anything; a statement with no readable <c>Effect</c> is
    /// skipped rather than assumed to allow, since assuming would fabricate access no policy
    /// actually grants.
    /// </summary>
    private static List<GrantTarget> ParseTargets(string policyBody)
    {
        var targets = new List<GrantTarget>();

        foreach (var statement in ExtractStatementObjects(policyBody))
        {
            var effect = EffectField().Match(statement);
            if (!effect.Success || !string.Equals(effect.Groups[1].Value, "Allow", StringComparison.OrdinalIgnoreCase))
                continue;

            var actionMatch = ActionField().Match(statement);
            var resourceMatch = ResourceField().Match(statement);
            if (!resourceMatch.Success) continue;

            var resourceText = resourceMatch.Groups[1].Value;
            var actionText = actionMatch.Success ? actionMatch.Groups[1].Value : string.Empty;

            // Prefer a direct reference — it names an exact node this seam can point to. Only
            // when there is nothing direct to point to does a wildcard signal (Resource: "*" or
            // a service action wildcard like s3:*) trigger widening; per the ticket, that
            // widened edge must still be produced, never dropped.
            var directReferences = TypeDotNameReference().Matches(resourceText)
                .Select(m => $"{m.Groups[1].Value}.{m.Groups[2].Value}")
                .Distinct(StringComparer.Ordinal)
                .ToList();

            if (directReferences.Count > 0)
            {
                targets.AddRange(directReferences.Select(address => new GrantTarget(false, address, null)));
                continue;
            }

            var resourceIsWildcard = resourceText.Contains('*');
            var actionServicePrefix = InferServicePrefixFromActions(actionText);
            var actionIsWildcard = actionText.Contains('*');

            if (resourceIsWildcard || actionIsWildcard)
                targets.Add(new GrantTarget(true, null, actionServicePrefix));

            // Neither a resolvable reference nor a wildcard signal — e.g. a hardcoded ARN for a
            // resource this Terraform config never declares. Nothing to point to and nothing to
            // widen; silently contributes no target rather than fabricating one.
        }

        return targets;
    }

    /// <summary>
    /// The single AWS service every action in this statement names, or null when the actions
    /// span more than one service (or none could be read) — null means "widen to every known
    /// Resource-typed node" rather than guessing a service.
    /// </summary>
    private static string? InferServicePrefixFromActions(string actionText)
    {
        var services = ActionServicePrefix().Matches(actionText)
            .Select(m => m.Groups[1].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return services.Count == 1 ? services[0] : null;
    }

    /// <summary>
    /// Best-effort service guess from a managed policy's ARN, e.g.
    /// <c>arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess</c> → <c>s3</c>. AWS's managed-policy
    /// names are not machine-parseable in general; this only recognizes the handful of name
    /// fragments in <see cref="ManagedPolicyServiceHints"/> and returns null (widen to
    /// everything) for anything else, rather than guessing wrong.
    /// </summary>
    private static string? InferServiceFromManagedPolicyArn(string policyArn)
    {
        var policyName = policyArn[(policyArn.LastIndexOf('/') + 1)..];

        foreach (var (hint, servicePrefix) in ManagedPolicyServiceHints)
        {
            if (policyName.Contains(hint, StringComparison.OrdinalIgnoreCase))
                return servicePrefix;
        }

        return null;
    }

    private static IEnumerable<string> ExtractNestedBlocks(string body, string keyword)
    {
        foreach (Match header in Regex.Matches(body, $@"{Regex.Escape(keyword)}\s*\{{"))
        {
            var bodyStart = header.Index + header.Length;
            var bodyEnd = FindMatchingBrace(body, bodyStart);
            if (bodyEnd >= 0) yield return body[bodyStart..bodyEnd];
        }
    }

    /// <summary>Every top-level <c>{...}</c> object inside the array following a
    /// <c>Statement</c> keyword, at the array's own nesting depth — so a statement's own nested
    /// objects (e.g. a <c>Condition</c> block) are captured as part of that statement's text,
    /// not split out as siblings.</summary>
    private static IEnumerable<string> ExtractStatementObjects(string body)
    {
        var statementIndex = body.IndexOf("Statement", StringComparison.Ordinal);
        if (statementIndex < 0) yield break;

        var arrayStart = body.IndexOf('[', statementIndex);
        if (arrayStart < 0) yield break;

        var i = arrayStart + 1;
        var arrayDepth = 1;

        while (i < body.Length && arrayDepth > 0)
        {
            switch (body[i])
            {
                case '[':
                    arrayDepth++;
                    i++;
                    break;
                case ']':
                    arrayDepth--;
                    i++;
                    break;
                case '{' when arrayDepth == 1:
                    var objectEnd = FindMatchingBrace(body, i + 1);
                    if (objectEnd < 0) yield break;
                    yield return body[(i + 1)..objectEnd];
                    i = objectEnd + 1;
                    break;
                default:
                    i++;
                    break;
            }
        }
    }

    /// <summary>Index of the <c>}</c> closing the brace already consumed just before
    /// <paramref name="bodyStart"/>, or -1 if the braces never balance. Mirrors
    /// <c>TerraformHclParser.FindMatchingBrace</c> exactly, kept as its own copy per this
    /// class's doc remarks.</summary>
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

/// <param name="IsWildcard">True when this target has no single resolvable address — the
/// statement's Resource and/or Action used a wildcard, so this represents "every resource the
/// wildcard could plausibly reach" rather than one named ARN.</param>
/// <param name="ResourceAddress">The Terraform address (<c>type.name</c>) this target resolves
/// to, when <paramref name="IsWildcard"/> is false.</param>
/// <param name="ServicePrefix">When <paramref name="IsWildcard"/> is true: the single AWS
/// service the wildcard was scoped to (e.g. <c>s3</c>), if one could be inferred — narrows
/// widening to Terraform resource types starting with <c>aws_{ServicePrefix}_</c>. Null means
/// "could not narrow it — widen to every known Resource-typed node".</param>
internal sealed record GrantTarget(bool IsWildcard, string? ResourceAddress, string? ServicePrefix);

/// <param name="RoleIdentifier">The Terraform resource name of the granted role, e.g.
/// <c>order_task_role</c> — not yet a canonical NodeId; <c>RoleResourceSeamReader</c> builds
/// that.</param>
internal sealed record RoleResourceGrant(string RoleIdentifier, IReadOnlyList<GrantTarget> Targets);
