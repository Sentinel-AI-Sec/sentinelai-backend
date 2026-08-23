using System.Text.Json;
using SentinelAI.Application.Features.Benchmark;
using SentinelAI.Benchmark;

// SEC-39: run the scorer over a SEC-38 benchmark corpus and print precision and recall per
// category for SentinelAI, SonarQube and Snyk side by side.
//
// Reading only. This never scans, never embeds and never writes to the corpus — SEC-38's
// "separate store, never embedded into RAG" is preserved here by having no code path that could
// break it.

const string Usage = """
    sentinelai-benchmark — precision/recall vs SonarQube & Snyk (SEC-39)

      sentinelai-benchmark --corpus <dir> [--out <file.md>] [--json <file.json>] [--window <n>]

      --corpus   The benchmark corpus. Expects corpus.json, labels/*.json and results/*.
      --out      Write the Markdown report here as well as to stdout.
      --json     Write the raw scores here, for a chart or a spreadsheet.
      --window   Line tolerance when matching a report to a label. Default 3; 0 is exact.

    Corpus layout:

      <corpus>/
        corpus.json              name and version
        labels/*.json            GroundTruthLabel[] — both vulnerable and clean locations
        results/sentinelai.json  ToolFinding[] or SARIF
        results/sonarqube.sarif  SARIF
        results/snyk.sarif       SARIF

    Exit codes: 0 report produced, 1 bad arguments, 2 the corpus could not be read.
    """;

var options = CommandLine.Parse(args);

if (options is null)
{
    Console.Error.WriteLine(Usage);
    return 1;
}

try
{
    var labels = CorpusReader.ReadLabels(options.Corpus);
    var projects = labels.Select(l => l.Project).ToHashSet(StringComparer.OrdinalIgnoreCase);
    var findings = CorpusReader.ReadFindings(options.Corpus, projects);

    var report = BenchmarkScorer.Score(
        corpus: CorpusReader.DescribeCorpus(options.Corpus),
        labels: labels,
        findings: findings,
        window: new MatchWindow(options.Window));

    var markdown = BenchmarkReportRenderer.ToMarkdown(report);
    Console.WriteLine(markdown);

    if (options.MarkdownOut is { } markdownPath)
    {
        File.WriteAllText(markdownPath, markdown);
        Console.Error.WriteLine($"wrote {markdownPath}");
    }

    if (options.JsonOut is { } jsonPath)
    {
        File.WriteAllText(
            jsonPath,
            JsonSerializer.Serialize(report.Scores, new JsonSerializerOptions { WriteIndented = true }));

        Console.Error.WriteLine($"wrote {jsonPath}");
    }

    // Deliberately not a threshold gate. A benchmark that fails a build below some precision
    // turns into a number people tune rather than a measurement they read, and the figure SEC-39
    // asks for is the one nobody was incentivised to move.
    return 0;
}
catch (Exception ex) when (ex is InvalidOperationException or IOException or JsonException)
{
    Console.Error.WriteLine($"could not read the corpus at '{options.Corpus}': {ex.Message}");
    return 2;
}

/// <summary>The runner's arguments.</summary>
internal sealed record BenchmarkOptions(string Corpus, string? MarkdownOut, string? JsonOut, int Window);

/// <summary>
/// A three-flag parser, written out rather than taken as a dependency.
/// </summary>
/// <remarks>
/// The alternative is a command-line package for four options in a tool nobody runs in a loop.
/// Adding a dependency to the build for that is a worse trade than thirty lines here.
/// </remarks>
internal static class CommandLine
{
    public static BenchmarkOptions? Parse(string[] args)
    {
        string? corpus = null, markdown = null, json = null;
        var window = MatchWindow.Default.Lines;

        for (var i = 0; i < args.Length; i++)
        {
            var next = i + 1 < args.Length ? args[i + 1] : null;

            switch (args[i])
            {
                case "--corpus" when next is not null: corpus = next; i++; break;
                case "--out" when next is not null: markdown = next; i++; break;
                case "--json" when next is not null: json = next; i++; break;

                case "--window" when next is not null && int.TryParse(next, out var lines) && lines >= 0:
                    window = lines;
                    i++;
                    break;

                case "-h" or "--help": return null;

                // An unrecognised flag is refused rather than ignored: silently skipping
                // "--windwo 0" would print a report computed with a window the caller did not
                // ask for, and nothing about the output would say so.
                default: return null;
            }
        }

        return corpus is null || !Directory.Exists(corpus)
            ? null
            : new BenchmarkOptions(corpus, markdown, json, window);
    }
}
