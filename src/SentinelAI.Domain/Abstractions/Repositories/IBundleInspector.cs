namespace SentinelAI.Domain.Abstractions.Repositories;

public interface IBundleInspector
{
    Task<BundleInspection> InspectAsync(Stream bundle, CancellationToken ct);
}
 
/// <param name="IsValid">False when the guard tripped or the shape is unusable.</param>
/// <param name="Error">Operator-readable reason; goes straight into the 400 body.</param>
/// <param name="Entries">Every file path found inside the tarball, bundle-root relative.</param>
/// <param name="MetadataJson">The bundle's own metadata.json, if present.</param>
/// <param name="Sha256">Digest of the received bytes, for provenance.</param>
/// <param name="SizeBytes">Received size.</param>
/// <param name="RawBundle">
/// The exact bytes that were hashed, rewound to position 0. Non-null only when
/// <see cref="IsValid"/> is true. The caller owns this and must dispose it once storage is
/// done with it. It exists so a caller never has to read the original upload stream a
/// second time — that stream may be forward-only, and re-reading it would silently persist
/// a truncated or empty bundle.
/// </param>
public sealed record BundleInspection(
    bool IsValid,
    string? Error,
    IReadOnlyList<string> Entries,
    string? MetadataJson,
    string Sha256,
    long SizeBytes,
    Stream? RawBundle)
{
    public static BundleInspection Rejected(string error) =>
        new(false, error, [], null, string.Empty, 0, null);
}