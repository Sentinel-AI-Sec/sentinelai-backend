using System.Text.Json;
using SentinelAI.Application.Features.Benchmark;

namespace SentinelAI.Benchmark;

/// <summary>
/// Reads a SEC-38 benchmark corpus off disk: its labels, and each tool's output over it.
/// </summary>
/// <remarks>
/// <para>
/// <b>The expected layout</b>, which is the corpus's contract with this runner:
/// </para>
/// <code>
/// &lt;corpus&gt;/
///   corpus.json              — name and version, for the report header
///   labels/*.json            — GroundTruthLabel[], one file per project or one for all
///   results/sentinelai.json  — ToolFinding[] or SARIF
///   results/sonarqube.sarif  — SARIF
///   results/snyk.sarif       — SARIF
/// </code>
/// <para>
/// <b>Both shapes are accepted for results</b>, because the three tools do not agree on one.
/// SonarQube and Snyk both export SARIF; SentinelAI's own findings come out of its read API as
/// its own JSON. Insisting on one shape would mean writing a conversion script that lives
/// outside this repository, is run by hand, and is the first thing to go stale.
/// </para>
/// <para>
/// <b>The corpus is never embedded.</b> This reads it and nothing else — no Qdrant client, no
/// embedder, no write path of any kind. SEC-38's "separate store, never embedded into RAG" holds
/// here by construction, and the acceptance test for it is that this file has no dependency that
/// could break it.
/// </para>
/// </remarks>
internal static class CorpusReader
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    /// <summary>The corpus's own name and version, or a fallback derived from the directory.</summary>
    public static string DescribeCorpus(string root)
    {
        var manifest = Path.Combine(root, "corpus.json");

        if (!File.Exists(manifest))
            return $"{Path.GetFileName(Path.TrimEndingDirectorySeparator(root))} (no corpus.json)";

        using var document = JsonDocument.Parse(File.ReadAllText(manifest));
        var element = document.RootElement;

        var name = element.TryGetProperty("name", out var n) ? n.GetString() : null;
        var version = element.TryGetProperty("version", out var v) ? v.GetString() : null;

        return string.Join(" ", new[] { name, version }.Where(s => !string.IsNullOrWhiteSpace(s)))
            is { Length: > 0 } described
            ? described
            : Path.GetFileName(Path.TrimEndingDirectorySeparator(root));
    }

    /// <summary>Every label under <c>labels/</c>, from every file.</summary>
    /// <exception cref="InvalidOperationException">The directory is missing or holds no labels.</exception>
    public static IReadOnlyList<GroundTruthLabel> ReadLabels(string root)
    {
        var directory = Path.Combine(root, "labels");

        if (!Directory.Exists(directory))
            throw new InvalidOperationException($"no labels directory at '{directory}'");

        var labels = new List<GroundTruthLabel>();

        foreach (var file in Directory.EnumerateFiles(directory, "*.json").Order(StringComparer.Ordinal))
        {
            var read = JsonSerializer.Deserialize<List<GroundTruthLabel>>(File.ReadAllText(file), Json);

            if (read is null || read.Count == 0)
            {
                // Refused rather than skipped. A labels file that parses to nothing is almost
                // always a shape mismatch, and silently scoring against fewer labels than the
                // corpus contains inflates precision and deflates recall with no sign anywhere.
                throw new InvalidOperationException($"'{file}' parsed to no labels; check its shape");
            }

            labels.AddRange(read);
        }

        if (labels.Count == 0)
            throw new InvalidOperationException($"'{directory}' contains no label files");

        var duplicates = labels.GroupBy(l => l.Id, StringComparer.Ordinal)
            .Where(g => g.Count() > 1)
            .Select(g => g.Key)
            .ToList();

        if (duplicates.Count > 0)
        {
            // Ids are how a disputed classification is looked up, so two labels sharing one is a
            // corpus defect that makes the report unciteable.
            throw new InvalidOperationException(
                $"duplicate label id(s): {string.Join(", ", duplicates.Take(10))}");
        }

        return labels;
    }

    /// <summary>Every tool's findings under <c>results/</c>, keyed by the file's own name.</summary>
    /// <remarks>
    /// The tool name comes from the file name — <c>results/snyk.sarif</c> is Snyk — so adding a
    /// fourth tool to the comparison is dropping a file in, not editing this reader.
    /// </remarks>
    /// <param name="root">The corpus directory.</param>
    /// <param name="projects">
    /// The project names the labels use. Passed through to the SARIF reader, which needs them to
    /// split an absolute build-agent path correctly — without them, every SonarQube finding
    /// lands in a project called <c>home</c> and matches nothing.
    /// </param>
    public static IReadOnlyList<ToolFinding> ReadFindings(string root, IReadOnlySet<string>? projects = null)
    {
        var directory = Path.Combine(root, "results");

        if (!Directory.Exists(directory))
            throw new InvalidOperationException($"no results directory at '{directory}'");

        var findings = new List<ToolFinding>();

        foreach (var file in Directory.EnumerateFiles(directory).Order(StringComparer.Ordinal))
        {
            var tool = Path.GetFileNameWithoutExtension(file).ToLowerInvariant();
            var text = File.ReadAllText(file);

            findings.AddRange(LooksLikeSarif(text)
                ? SarifToolFindings.Read(text, tool, projects)
                : JsonSerializer.Deserialize<List<ToolFinding>>(text, Json) ?? []);
        }

        return findings;
    }

    /// <summary>
    /// Whether a results file is SARIF rather than a plain <see cref="ToolFinding"/> array.
    /// </summary>
    /// <remarks>
    /// Decided by the document's own shape rather than by its extension: exports get renamed,
    /// and a <c>.json</c> holding SARIF is common enough that keying on the extension would read
    /// a real file as an empty one — the failure mode that looks like a tool finding nothing.
    /// </remarks>
    private static bool LooksLikeSarif(string text)
    {
        using var document = JsonDocument.Parse(text);

        return document.RootElement.ValueKind == JsonValueKind.Object
            && document.RootElement.TryGetProperty("runs", out var runs)
            && runs.ValueKind == JsonValueKind.Array;
    }
}
