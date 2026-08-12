using System.Text.RegularExpressions;

namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-19, code side: reads the image name a Dockerfile identifies itself as building.
/// </summary>
/// <remarks>
/// A Dockerfile has no field that names the image it produces — that name is supplied
/// externally, by whatever <c>docker build -t &lt;name&gt;</c> invocation (a CI script, most
/// often) builds it. Since this ticket's fixtures include no CI script to read that from, this
/// reads a single, explicit, self-declared signal instead: a
/// <c>LABEL org.sentinelai.image="&lt;name&gt;"</c> line. This is an assumed convention, not a
/// Docker or OCI standard — flagged here because no ticket owns it formally, the same way
/// <see cref="ProvisionalCodeNodeResolver"/> flags the Code-node identity assumption. A
/// Dockerfile without this label yields no image name, which this seam treats the same as "the
/// code side names no image" — see <see cref="CodeInfraSeamReader"/>.
/// </remarks>
internal static partial class DockerfileImageNameExtractor
{
    [GeneratedRegex(""""LABEL\s+org\.sentinelai\.image\s*=\s*"([^"]+)"""", RegexOptions.CultureInvariant)]
    private static partial Regex ImageLabel();

    public static string? TryExtractImageName(string dockerfileText)
    {
        if (string.IsNullOrWhiteSpace(dockerfileText)) return null;

        var match = ImageLabel().Match(dockerfileText);
        return match.Success ? match.Groups[1].Value : null;
    }
}
