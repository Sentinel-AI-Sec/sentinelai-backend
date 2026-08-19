namespace SentinelAI.Domain.Abstractions;

/// <summary>
/// Resolves an infrastructure finding's reported location — a <c>.tf</c> file and a line — to
/// the canonical node key of the Terraform resource that line sits inside.
/// </summary>
/// <remarks>
/// <para>
/// This closes the node-granularity gap <c>docs/Walking_Skeleton.md</c> records as the biggest
/// TODO left open by SEC-17: <c>FindingUnifier</c> builds file-grained node references
/// (<c>s3:infra/iam.tf</c>) because a file path is the finest subject a scanner reports, while
/// the graph readers build resource-grained ones (<c>iam_role:order_task_role</c>). The two node
/// sets sit side by side describing the same physical resources, so no infra finding decorates
/// any infra node and no chain can be seeded from one. SEC-20 needs hot seeds, so SEC-20 owns
/// closing it.
/// </para>
/// <para>
/// A port rather than a helper because resolving it means parsing Terraform source, which is
/// Infrastructure's business — the Application-layer decorator that consumes this only ever
/// sees a dictionary of strings.
/// </para>
/// </remarks>
public interface IInfraFindingLocator
{
    /// <summary>
    /// Maps each of <paramref name="findingLocations"/> to a canonical node key, omitting the
    /// ones that could not be placed.
    /// </summary>
    /// <param name="hclFiles">Bundle-relative filename to decoded <c>.tf</c> text, as
    /// <c>IBundleStore.OpenGraphInputsAsync</c> returns them. Their paths are bundle-relative
    /// (<c>graph-inputs/infra/iam.tf</c>) while a finding's is repo-relative
    /// (<c>infra/iam.tf</c>), so an implementation has to match on path suffix rather than on
    /// equality.</param>
    /// <param name="findingLocations">Normalized <c>path</c> or <c>path:line</c> values, exactly
    /// as <c>Finding.Location</c> carries them.</param>
    /// <returns>Location → node key. A location absent from the result is one no resource block
    /// claimed; the caller leaves that finding unattached rather than guessing.</returns>
    IReadOnlyDictionary<string, string> Locate(
        IReadOnlyDictionary<string, string> hclFiles, IEnumerable<string> findingLocations);
}
