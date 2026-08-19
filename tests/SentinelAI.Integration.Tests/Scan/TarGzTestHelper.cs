using System.Formats.Tar;
using System.IO.Compression;
using System.Text;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>Builds tiny in-memory <c>.tar.gz</c> bundles for the SEC-13 ingest tests.</summary>
internal static class TarGzTestHelper
{
    public static MemoryStream Build(IReadOnlyDictionary<string, string> files)
    {
        var archive = new MemoryStream();

        using (var gzip = new GZipStream(archive, CompressionLevel.Fastest, leaveOpen: true))
        using (var tar = new TarWriter(gzip, leaveOpen: false))
        {
            foreach (var (name, content) in files)
            {
                var entry = new PaxTarEntry(TarEntryType.RegularFile, name)
                {
                    DataStream = new MemoryStream(Encoding.UTF8.GetBytes(content)),
                };
                tar.WriteEntry(entry);
            }
        }

        archive.Position = 0;
        return archive;
    }

    /// <summary>A bundle that passes every guard: metadata.json, a findings/ entry, no source.</summary>
    public static MemoryStream ValidBundle(string projectId = "11111111-1111-1111-1111-111111111111") =>
        Build(new Dictionary<string, string>
        {
            ["metadata.json"] = $$"""{"project_id":"{{projectId}}","commit_sha":"abc123"}""",
            ["findings/osv.sarif"] = "{}",
        });
}
