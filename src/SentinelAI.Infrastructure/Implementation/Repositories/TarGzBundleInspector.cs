using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using SentinelAI.Domain.Abstractions.Repositories;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

/// <summary>
/// Unpacks the uploaded <c>.tar.gz</c>, hashes it, and refuses anything that carries
/// application source or does not look like a SentinelAI bundle.
/// </summary>
/// <remarks>
/// This mirrors <c>scripts/assert-no-source.sh</c> in sentinelai-action. The runner runs
/// that guard twice already; this is the third pass and the only one on infrastructure we
/// control. "Your code never leaves your runner" is the product's core privacy promise —
/// it has to be enforced by the party that would be embarrassed if it were false.
/// <para>
/// Nothing is extracted to disk. Entries are enumerated and their names checked; only
/// <c>metadata.json</c> is read into memory, because we compare it against the manifest.
/// </para>
/// </remarks>
public sealed partial class TarGzBundleInspector(ILogger<TarGzBundleInspector> logger) : IBundleInspector
{
    /// <summary>
    /// Application source in any language we might plausibly meet. <c>.csproj</c> and
    /// <c>packages.lock.json</c> are manifests, not source, and stay allowed.
    /// </summary>
    [GeneratedRegex(
        @"\.(cs|vb|fs|cshtml|razor|aspx|java|kt|py|rb|php|go|rs|ts|tsx|jsx|c|cc|cpp|h|hpp|m|swift|scala)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BlockedSourceExtension();
 
    /// <summary>A bundle with no findings at all has nothing for Pipeline B to do.</summary>
    private const string FindingsPrefix = "findings/";
 
    private const long MaxBundleBytes = 64L * 1024 * 1024;
    private const long MaxUncompressedBytes = 512L * 1024 * 1024;
    private const int MaxEntries = 5_000;
 
    public async Task<BundleInspection> InspectAsync(Stream bundle, CancellationToken ct)
    {
        if (bundle.CanSeek) bundle.Position = 0;
 
        // Hash the received bytes first, on the way to a rewindable buffer. The digest has
        // to describe exactly what arrived, so it is taken before anything is interpreted.
        var buffer = new MemoryStream();
        using var sha = SHA256.Create();
        var read = new byte[81920];
        long total = 0;
        int n;

        // A rejection never hands the buffer back to the caller, so nothing else will
        // dispose it — every early return goes through here instead of a bare
        // BundleInspection.Rejected(...) call.
        async Task<BundleInspection> Reject(string error)
        {
            await buffer.DisposeAsync();
            return BundleInspection.Rejected(error);
        }

        while ((n = await bundle.ReadAsync(read, ct)) > 0)
        {
            total += n;
            if (total > MaxBundleBytes)
                return await Reject($"bundle exceeds the {MaxBundleBytes / (1024 * 1024)} MB ingest limit");

            sha.TransformBlock(read, 0, n, null, 0);
            await buffer.WriteAsync(read.AsMemory(0, n), ct);
        }

        sha.TransformFinalBlock([], 0, 0);
        var digest = Convert.ToHexStringLower(sha.Hash!);

        if (total == 0)
            return await Reject("the uploaded bundle is empty");
 
        buffer.Position = 0;
 
        var entries = new List<string>();
        string? metadataJson = null;
        long uncompressed = 0;
 
        try
        {
            await using var gzip = new GZipStream(buffer, CompressionMode.Decompress, leaveOpen: true);
            await using var tar = new TarReader(gzip, leaveOpen: false);
 
            while (await tar.GetNextEntryAsync(cancellationToken: ct) is { } entry)
            {
                if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile))
                    continue;
 
                var name = Normalize(entry.Name);
 
                // A tarball that escapes its own root is hostile, not malformed.
                if (name.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(name))
                    return BundleInspection.Rejected($"bundle contains a path-traversal entry: {entry.Name}");
 
                if (entries.Count >= MaxEntries)
                    return BundleInspection.Rejected($"bundle exceeds {MaxEntries} entries");
 
                uncompressed += Math.Max(entry.Length, 0);
                if (uncompressed > MaxUncompressedBytes)
                    return BundleInspection.Rejected("bundle expands beyond the decompression limit");
 
                entries.Add(name);
 
                if (name.Equals("metadata.json", StringComparison.OrdinalIgnoreCase) && entry.DataStream is not null)
                {
                    using var reader = new StreamReader(entry.DataStream);
                    metadataJson = await reader.ReadToEndAsync(ct);
                }
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException or FormatException)
        {
            return await Reject($"bundle is not a readable .tar.gz: {ex.Message}");
        }
 
        // ---- The guard ------------------------------------------------------------------
        var offenders = entries.Where(e => BlockedSourceExtension().IsMatch(e)).ToList();
        if (offenders.Count > 0)
        {
            // Logged loudly: a bundle carrying source means the runner-side guard failed,
            // which is a defect in the Action worth chasing down, not a routine 400.
            logger.LogError(
                "Source guard tripped on ingest: {Count} source file(s) in bundle {Sha}. First: {Sample}",
                offenders.Count, digest, string.Join(", ", offenders.Take(5)));
 
            return await Reject(
                $"the bundle contains application source ({offenders.Count} file(s)) and was refused; " +
                "this indicates the runner-side guard did not run");
        }

        // ---- Shape ----------------------------------------------------------------------
        if (metadataJson is null)
            return await Reject("bundle has no metadata.json at its root");

        if (!entries.Any(e => e.StartsWith(FindingsPrefix, StringComparison.OrdinalIgnoreCase)))
            return await Reject("bundle has no findings/ directory — nothing to normalize");

        logger.LogInformation(
            "Bundle accepted: {Entries} entries, {Bytes} bytes, sha256 {Sha}",
            entries.Count, total, digest);

        // Rewound so the caller (the bundle store) can persist exactly these bytes without
        // re-reading the original upload stream, which may be forward-only.
        buffer.Position = 0;
        return new BundleInspection(true, null, entries, metadataJson, digest, total, buffer);
    }
 
    /// <summary>Tar writes leading <c>./</c>; the manifest does not. Compare like for like.</summary>
    private static string Normalize(string name) =>
        name.Replace('\\', '/').TrimStart('.', '/');
}
