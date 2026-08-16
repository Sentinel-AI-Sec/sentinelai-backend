using System.Text.Json;

namespace SentinelAI.Integration.Tests.Knowledge;

/// <summary>
/// Finds the corpus this developer is actually configured against, so the live tests run without
/// anyone having to remember an environment variable.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists.</b> Gating the live tests behind <c>SENTINELAI_CORPUS_URL</c> meant they
/// skipped on every ordinary <c>dotnet test</c> — including the run someone does before opening a
/// PR. A test that only runs when you remember to set a variable is a test that protects nothing,
/// and reporting it as "skipped" makes that invisible rather than obvious.
/// </para>
/// <para>
/// So the order is: an explicit environment variable first (CI, or overriding for a one-off), then
/// <c>appsettings.Development.json</c> — the file the developer already configured to run the API
/// against their corpus. It is git-ignored, so reading it here keeps credentials out of the
/// repository while still letting the tests run by default on a machine that has a corpus.
/// </para>
/// <para>
/// On a machine with neither — a fresh clone, or CI — both come back null and the tests skip,
/// which is the honest outcome: there is no corpus to test against.
/// </para>
/// </remarks>
internal static class LocalDev
{
    private const string SettingsPath = "src/SentinelAI.Api/appsettings.Development.json";

    private static readonly Lazy<JsonElement?> Knowledge = new(ReadKnowledgeSection);

    /// <summary>The corpus endpoint, from the environment or the developer's own settings.</summary>
    public static string? CorpusUrl =>
        Environment.GetEnvironmentVariable("SENTINELAI_CORPUS_URL") is { Length: > 0 } fromEnv
            ? fromEnv
            : Setting("Endpoint");

    /// <summary>The corpus API key. Empty is valid — a local container needs none.</summary>
    public static string CorpusKey =>
        Environment.GetEnvironmentVariable("SENTINELAI_CORPUS_KEY") is { Length: > 0 } fromEnv
            ? fromEnv
            : Setting("ApiKey") ?? string.Empty;

    private static string? Setting(string name) =>
        Knowledge.Value?.TryGetProperty(name, out var value) == true
        && value.ValueKind == JsonValueKind.String
        && value.GetString() is { Length: > 0 } text
            ? text
            : null;

    /// <summary>
    /// Reads the <c>Knowledge</c> section out of the developer's local settings, or null.
    /// </summary>
    /// <remarks>
    /// The repository root is found by walking up for the solution file rather than by counting
    /// <c>../</c> from the test binary — that count changes with the target framework and the
    /// build configuration, and silently resolves to nothing when it does.
    /// </remarks>
    private static JsonElement? ReadKnowledgeSection()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "SentinelAI.slnx")))
            directory = directory.Parent;

        if (directory is null) return null;

        var path = Path.Combine(directory.FullName, SettingsPath);
        if (!File.Exists(path)) return null;

        try
        {
            using var document = JsonDocument.Parse(
                File.ReadAllText(path),
                new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });

            return document.RootElement.TryGetProperty("Knowledge", out var knowledge)
                ? knowledge.Clone()
                : null;
        }
        catch (JsonException)
        {
            // A malformed local settings file is the developer's problem to see when they run the
            // API, not a reason to fail test discovery.
            return null;
        }
    }
}
