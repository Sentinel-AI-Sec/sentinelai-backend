namespace SentinelAI.Infrastructure.Graph;

/// <summary>
/// SEC-19, step 3: normalizes an image reference down to a bare repository name so the
/// Dockerfile side and the Terraform side can be compared name-for-name — stripping a registry
/// host prefix (<c>123456789.dkr.ecr.us-east-1.amazonaws.com/</c>) and a trailing tag or digest
/// (<c>:latest</c>, <c>@sha256:...</c>).
/// </summary>
internal static class ImageNameNormalizer
{
    public static string Normalize(string imageRef)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(imageRef);
        var value = imageRef.Trim();

        // A registry host is only ever the FIRST path segment, and only counts as one when it
        // looks like a host (contains '.' or ':') — otherwise "tinyapp/order" would lose
        // "tinyapp" to this step by mistake, since a bare Docker Hub org has no such marker.
        var firstSlash = value.IndexOf('/');
        if (firstSlash > 0)
        {
            var firstSegment = value[..firstSlash];
            if (firstSegment.Contains('.') || firstSegment.Contains(':'))
                value = value[(firstSlash + 1)..];
        }

        var digestAt = value.IndexOf('@');
        if (digestAt >= 0) value = value[..digestAt];

        // A tag's ':' can only appear after the last '/' — a registry port's ':' (already
        // stripped above with its host) would otherwise be mistaken for one.
        var lastSlash = value.LastIndexOf('/');
        var tagColon = value.IndexOf(':', lastSlash + 1);
        if (tagColon >= 0) value = value[..tagColon];

        return value.Trim().ToLowerInvariant();
    }
}
