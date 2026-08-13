namespace SentinelAI.Domain.Enums;

/// <summary>
/// The ATT&amp;CK tactic a node occupies in an exploit chain, ordered along the kill chain
/// (SEC-20 step 4). Traversal only moves forward through this ordering, which is what stops
/// bounded candidate generation from emitting paths that read as attack chains but describe
/// an attacker walking backwards.
/// </summary>
/// <remarks>
/// <para>
/// Only the tactics this graph's node vocabulary can actually occupy are listed. The numeric
/// values are ATT&amp;CK's own <c>TA</c> ids with the prefix dropped, so the enum's order is
/// ATT&amp;CK's order rather than one invented here, and a member can be added later without
/// renumbering the ones around it — <c>CredentialAccess</c> (TA0006) already has its slot free
/// between <see cref="PrivilegeEscalation"/> and <see cref="Collection"/>.
/// </para>
/// <para>
/// <b>Ordering is load-bearing and pinned by a test.</b> <see cref="AttackTacticExtensions.Precedes"/>
/// compares these values directly. Reordering them silently changes which candidate paths
/// survive traversal — the same class of failure as reordering <see cref="Confidence"/>, and
/// guarded the same way.
/// </para>
/// </remarks>
public enum AttackTactic
{
    /// <summary>TA0001. Where an attacker gets in: a vulnerable dependency is the fixture's door.</summary>
    InitialAccess = 1,

    /// <summary>TA0002. Attacker-controlled code running: the code unit and the image it builds.</summary>
    Execution = 2,

    /// <summary>TA0003. A foothold that survives: the deployed workload the code runs as.</summary>
    Persistence = 3,

    /// <summary>TA0004. Wider rights than the foothold started with: the role the workload assumes.</summary>
    PrivilegeEscalation = 4,

    /// <summary>TA0009. Reaching the data itself: the crown-jewel resource at the end of the chain.</summary>
    Collection = 9,
}

/// <summary>
/// The node-type → tactic map and the ordering rule traversal applies to it.
/// </summary>
/// <remarks>
/// The map lives next to the enum rather than in <see cref="NodeTypeExtensions"/> because it is
/// chaining's opinion about the node vocabulary, not part of the vocabulary itself: a node key's
/// spelling crosses repository boundaries (see <see cref="NodeTypeExtensions.Prefix"/>), whereas
/// which tactic a task definition occupies is a judgement this backend makes and may revise.
/// </remarks>
public static class AttackTacticExtensions
{
    /// <summary>
    /// The tactic a node of this type occupies.
    /// </summary>
    /// <remarks>
    /// <see cref="NodeType.Task"/> maps to <see cref="AttackTactic.Persistence"/> rather than
    /// Lateral Movement (TA0008), which is the reading that first suggests itself for "moving
    /// to a workload". Deliberate: in this graph a workload is reached from the code deployed
    /// into it and is where the attacker then escalates <em>from</em>, so placing it after
    /// Privilege Escalation in the ordering would reject the flagship chain — the exact
    /// zero-chains failure mode SEC-17's orientation guard exists to prevent, arriving one
    /// stage later.
    /// </remarks>
    public static AttackTactic Tactic(this NodeType type) => type switch
    {
        NodeType.Pkg => AttackTactic.InitialAccess,
        NodeType.Code => AttackTactic.Execution,
        NodeType.Image => AttackTactic.Execution,
        NodeType.Task => AttackTactic.Persistence,
        NodeType.IamRole => AttackTactic.PrivilegeEscalation,
        NodeType.Resource => AttackTactic.Collection,

        _ => throw new ArgumentOutOfRangeException(
            nameof(type), type, "No ATT&CK tactic defined for this node type."),
    };

    /// <summary>
    /// True when a chain may step from <paramref name="from"/> to <paramref name="to"/>: the
    /// kill chain moves forward or stays put, never back.
    /// </summary>
    /// <remarks>
    /// Equal tactics are allowed — a code node reaching another code node is still Execution,
    /// and rejecting it would break same-layer movement that is genuinely how an attacker
    /// spreads. What it rejects is the backwards step, e.g. the <c>iam_role → task</c> edge the
    /// infra spine produces by reversing every Terraform dependency: a role does not lead an
    /// attacker back into Persistence, and a candidate that claims it does is noise.
    /// </remarks>
    public static bool Precedes(this AttackTactic from, AttackTactic to) => from <= to;
}
