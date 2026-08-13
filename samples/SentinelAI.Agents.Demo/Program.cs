using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.Configuration;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Agents.Demo;
using SentinelAI.Infrastructure.Agents.Executors;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;

// SentinelAI SEC-02 demo runner. Drives the three scenarios the Sprint 1 demo calls for.
//
//   dotnet run -- debate      Red -> Blue -> Reporter over shared session state
//   dotnet run -- turncap     turn-cap terminates the debate; Reporter still outputs
//   dotnet run -- resume      crash mid-run, then resume from the last checkpoint
//   dotnet run -- unresolved  a load-bearing join cannot be confirmed; the chain is
//                             surfaced as unverified rather than dropped or confirmed
//
// Add --provider nim (or anthropic / azureopenai) to run against a live model.
// The key is read from SENTINELAI_API_KEY.

// The console defaults to the system code page on Windows, which renders the spinner and
// tick glyphs as "?" and "v". Best-effort: a console that refuses UTF-8 still runs fine.
try { Console.OutputEncoding = System.Text.Encoding.UTF8; } catch (IOException) { }

var scenario = (args.FirstOrDefault() ?? "debate").ToLowerInvariant() switch
{
    "debate" => Scenario.Debate,
    "turncap" => Scenario.TurnCap,
    "resume" => Scenario.Resume,
    "unresolved" => Scenario.Unresolved,
    var other => Fail<Scenario>(
        $"Unknown scenario '{other}'. Use: debate | turncap | resume | unresolved")
};

// dev.json holds the per-agent keys and is git-ignored; user-secrets and environment
// variables layer on top so CI never needs a file on disk.
var configuration = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: true)
    .AddJsonFile("dev.json", optional: true, reloadOnChange: false)
    .AddUserSecrets(typeof(Program).Assembly, optional: true)
    .AddEnvironmentVariables()
    .Build();

var options = ModelOptionsLoader.Load(configuration);

// An explicit --provider always beats whatever the files said.
if (ProviderArg(args) is { } chosen) options.Provider = chosen;

// Fail before the first turn rather than three agents in, and name every agent that is
// missing a key instead of stopping at the first one.
if (options.Provider != ModelProvider.Scripted)
{
    var missing = options.AgentsMissingKeys(DebateWorkflow.ModelBackedRoles);
    if (missing.Count > 0)
    {
        Write(ConsoleColor.Red, $"  No API key for: {string.Join(", ", missing)}");
        Write(ConsoleColor.DarkGray,
            $"  Set SentinelAI:Models:Agents:<Agent>:ApiKey in dev.json, or export "
            + string.Join(" / ", missing.Select(ModelOptionsLoader.KeyVariableFor)));
        return 2;
    }
}

var debateOptions = new DebateOptions { MaxRounds = scenario == Scenario.TurnCap ? 2 : 3 };

Banner(scenario, options, debateOptions);

// SEC-31: rates for whichever provider ended up selected, so the demo closes with a real
// cost per tier rather than only a transcript. Read after the --provider override, or a run
// forced onto Azure would be billed at whatever the config file's provider charges.
var pricing = ProviderPricing.Load(configuration, options.Provider);

var workflow = DebateWorkflow.Build(new DemoChatClientFactory(options, scenario), debateOptions, pricing);
var runner = new DebateRunner(workflow);

var clock = System.Diagnostics.Stopwatch.StartNew();

Rule("Debate (live)");
var result = await runner.RunAsync(ScanBrief.Stub(), onEvent: e => OnEvent(e, clock));
var executedFirstPass = result.Turns.Count;

if (scenario == Scenario.Resume)
{
    Rule("Blue crashed. The run stopped without a verdict.");
    Write(ConsoleColor.DarkGray, $"  checkpoints written : {result.Checkpoints.Count}");
    Write(ConsoleColor.DarkGray, $"  audit produced      : {(result.Completed ? "yes" : "no")}");

    if (result.Checkpoints.Count == 0)
        return Fail<int>("No checkpoint to resume from.");

    Rule("Resuming from the last checkpoint...");
    result = await runner.ResumeAsync(result.Checkpoints[^1], onEvent: e => OnEvent(e, clock));

    // Turns in the audit that never re-executed were restored from the checkpoint.
    // That gap is AC2, made visible.
    var restored = (result.Audit?.Transcript.Count ?? 0) - result.Turns.Count;
    if (restored > 0)
        Write(ConsoleColor.DarkGray,
            $"  {restored} completed turn(s) restored from state, not re-run "
            + $"({result.Turns.Count} executed on resume).");
}

PrintAudit(result, scenario);
Write(ConsoleColor.DarkGray, $"  elapsed           : {clock.Elapsed.TotalSeconds:F1}s");
Console.WriteLine();
return result.Completed ? 0 : 1;

// ---------------------------------------------------------------- presentation --

static void Banner(Scenario scenario, ModelProviderOptions models, DebateOptions debate)
{
    Console.WriteLine();
    Write(ConsoleColor.Cyan, "  SentinelAI — SEC-02 agent orchestration skeleton");
    Write(ConsoleColor.DarkGray, $"  scenario {scenario}   provider {models.Provider}   turn-cap {debate.MaxRounds}");
    if (models.Provider != ModelProvider.Scripted)
        Write(ConsoleColor.DarkGray, $"  model    {models.ModelFor(ModelTier.High)}");
    Console.WriteLine();
}

/// <summary>
/// Reports the debate as it happens rather than after it finishes.
/// </summary>
/// <remarks>
/// A live model spends tens of seconds per turn. Printing only at the end meant the whole
/// run — eight model calls on a non-converging debate — produced no output at all until
/// it completed, which reads as a hang. Announcing each agent as it starts, and printing
/// its turn the moment it lands, makes the wait legible.
/// </remarks>
static void OnEvent(WorkflowEvent evt, System.Diagnostics.Stopwatch clock)
{
    switch (evt)
    {
        case AgentTurnEvent turn:
            PrintTurn(turn.Turn, clock);
            break;

        case ExecutorInvokedEvent invoked:
            Write(ConsoleColor.DarkGray, $"  [{clock.Elapsed.TotalSeconds,6:F1}s] {invoked.ExecutorId} thinking...");
            break;

        case ExecutorFailedEvent failed:
            Write(ConsoleColor.Yellow,
                $"  [{clock.Elapsed.TotalSeconds,6:F1}s] {failed.ExecutorId} failed: {failed.Data?.Message}");
            break;
    }
}

static void PrintTurn(DebateTurn turn, System.Diagnostics.Stopwatch clock)
{
    var colour = turn.Role switch
    {
        AgentRole.Red => ConsoleColor.Red,
        AgentRole.Blue => ConsoleColor.Blue,
        AgentRole.Orchestrator => ConsoleColor.DarkGray,
        _ => ConsoleColor.Green
    };

    ConsoleOut.Line();
    Write(colour, $"  [round {turn.Round}] {turn.Role}   ({clock.Elapsed.TotalSeconds:F1}s)");
    foreach (var line in Wrap(turn.Content, 78))
        ConsoleOut.Line($"    {line}");
    ConsoleOut.Line();
}

static void PrintAudit(DebateResult result, Scenario scenario)
{
    Rule("Outcome");

    if (result.Audit is not { } audit)
    {
        Write(ConsoleColor.Yellow, "  No audit produced — the run did not reach the Reporter.");
        return;
    }

    ConsoleOut.Line($"  rounds            : {audit.Rounds}");
    ConsoleOut.Line($"  turns             : {audit.Transcript.Count}");

    // Reports the outcome, not the raw Converged flag. A model that produced no parseable
    // verdict used to surface here as "converged: True", which read as a clean result.
    Write(audit.Outcome == DebateOutcome.Converged ? ConsoleColor.Gray : ConsoleColor.Yellow,
        $"  outcome           : {Describe(audit.Outcome)}");

    Write(audit.TerminatedByTurnCap ? ConsoleColor.Yellow : ConsoleColor.Gray,
        $"  ended by turn-cap : {audit.TerminatedByTurnCap}");

    Write(audit.WeakestJoin == Confidence.Certain ? ConsoleColor.Gray : ConsoleColor.Yellow,
        $"  weakest join      : {audit.WeakestJoin}");

    ConsoleOut.Line($"  checkpoints       : {result.Checkpoints.Count}");
    ConsoleOut.Line();

    PrintCost(audit.Cost);

    // AID-01 §3.3 separates these deliberately: an inferred edge is usable but flagged,
    // while only an unresolved edge is surfaced as a potential-chain-unverified.
    switch (audit.WeakestJoin)
    {
        case Confidence.Unresolved:
            Write(ConsoleColor.Yellow,
                "  Potential chain, unverified join — surfaced for human confirmation, not a verdict.");
            break;
        case Confidence.Inferred:
            Write(ConsoleColor.Yellow,
                "  Chain rests on an inferred join — usable, but flagged for extra scrutiny.");
            break;
    }

    Write(ConsoleColor.DarkGray, $"  {audit.Disclaimer}");

    if (scenario == Scenario.TurnCap && audit.TerminatedByTurnCap)
        Write(ConsoleColor.DarkGray, "  The Reporter still ran and still produced output. That is AC3.");

    if (scenario == Scenario.Unresolved && audit.WeakestJoin == Confidence.Unresolved)
        Write(ConsoleColor.DarkGray,
            "  The chain survived to the Reporter rather than being silently dropped.");

    Console.WriteLine();
}

/// <summary>
/// SEC-31's cost per audit, by tier. Tokens and money are printed side by side because only
/// the tokens are certain — the money is those tokens at a rate somebody configured.
/// </summary>
static void PrintCost(AuditCost cost)
{
    Rule("Cost");

    if (!cost.Measured)
    {
        Write(ConsoleColor.DarkGray, "  The provider reported no token usage for this run.");
        ConsoleOut.Line();
        return;
    }

    foreach (var tier in cost.ByTier)
    {
        var money = tier.Rated
            ? $"{tier.Cost:0.000000} {cost.Currency}"
            : "unpriced";

        ConsoleOut.Line(
            $"  {tier.Tier,-6}: {tier.Calls} call(s), {tier.Usage.InputTokens} in / "
            + $"{tier.Usage.OutputTokens} out  →  {money}");
    }

    Write(cost.FullyRated ? ConsoleColor.Gray : ConsoleColor.Yellow,
        $"  total : {cost.TotalCalls} call(s), {cost.TotalUsage.TotalTokens} tokens  →  "
        + $"{cost.Total:0.000000} {cost.Currency}");

    if (!cost.FullyRated)
    {
        Write(ConsoleColor.Yellow,
            "  A tier has no configured rate, so this total is an under-count, not the bill. "
            + $"Set {ModelPricing.SectionName}:<Tier>:InputPerMillionTokens / OutputPerMillionTokens.");
    }

    ConsoleOut.Line();
}

static string Describe(DebateOutcome outcome) => outcome switch
{
    DebateOutcome.Converged => "converged (Blue could not break the chain)",
    DebateOutcome.ChainBroken => "chain broken (Blue broke a link)",
    DebateOutcome.TurnCapped => "stopped by turn-cap (unresolved)",
    DebateOutcome.VerdictUnreadable => "NO VERDICT — Blue's response was not parseable",
    _ => outcome.ToString()
};

/// <summary>Null when --provider was not supplied, so configuration keeps its say.</summary>
static ModelProvider? ProviderArg(string[] args)
{
    var i = Array.FindIndex(args, a => a is "--provider" or "-p");
    if (i < 0 || i + 1 >= args.Length) return null;

    return Enum.TryParse<ModelProvider>(args[i + 1], ignoreCase: true, out var provider)
        ? provider
        : Fail<ModelProvider>($"Unknown provider '{args[i + 1]}'. "
            + $"Use: {string.Join(" | ", Enum.GetNames<ModelProvider>()).ToLowerInvariant()}");
}

static void Rule(string title)
{
    Write(ConsoleColor.DarkGray, $"  {new string('-', 78)}");
    Write(ConsoleColor.White, $"  {title}");
}

// Goes through ConsoleOut so a live spinner is erased before the line lands.
static void Write(ConsoleColor colour, string text) => ConsoleOut.Line(colour, text);

static IEnumerable<string> Wrap(string text, int width)
{
    var line = new System.Text.StringBuilder();
    foreach (var word in text.Split(' ', StringSplitOptions.RemoveEmptyEntries))
    {
        if (line.Length > 0 && line.Length + word.Length + 1 > width)
        {
            yield return line.ToString();
            line.Clear();
        }
        if (line.Length > 0) line.Append(' ');
        line.Append(word);
    }
    if (line.Length > 0) yield return line.ToString();
}

static T Fail<T>(string message)
{
    Write(ConsoleColor.Red, $"  {message}");
    Environment.Exit(2);
    return default!;
}
