using System.Diagnostics;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.AI;
using SentinelAI.Application.Debate;
using SentinelAI.Domain.Models;

namespace SentinelAI.Agents.Demo;

/// <summary>
/// Wraps an <see cref="IChatClient"/> with console output so the user can see when
/// each agent is calling the model and how long the call takes.
/// </summary>
/// <remarks>
/// Every console call here is best-effort. Carriage-return animation only works on a real
/// console: when output is redirected — a pipe, CI, an IDE window — <see cref="Console.WindowWidth"/>
/// throws <c>IOException: The handle is invalid</c>, and <c>\r</c> stops overwriting, so
/// the spinner both crashes and spams a line per frame. Progress reporting must never be
/// able to fail a turn that the model actually answered.
/// </remarks>
internal sealed class SpinnerChatClient(IChatClient inner, AgentRole role) : IChatClient
{
    private static readonly string[] SpinnerFrames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

    /// <summary>True only when stdout is a real console that can be animated in place.</summary>
    private static bool CanAnimate => !Console.IsOutputRedirected;

    private static ConsoleColor ColorFor(AgentRole role) => role switch
    {
        AgentRole.Orchestrator => ConsoleColor.Cyan,
        AgentRole.Red => ConsoleColor.Red,
        AgentRole.Blue => ConsoleColor.Blue,
        AgentRole.Reporter => ConsoleColor.Green,
        _ => ConsoleColor.Gray
    };

    public async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var colour = ColorFor(role);
        var sw = Stopwatch.StartNew();

        // Start the spinner on a background task.
        using var spinnerCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var spinnerTask = RunSpinnerAsync(role, colour, sw, spinnerCts.Token);

        try
        {
            var response = await inner
                .GetResponseAsync(messages, options, cancellationToken)
                .ConfigureAwait(false);

            sw.Stop();
            spinnerCts.Cancel();
            await AwaitSpinner(spinnerTask);

            // Clear the spinner line and print the completion message.
            ClearLine();
            Write(colour, $"  ✓ {role} responded in {sw.Elapsed.TotalSeconds:F1}s");

            return response;
        }
        catch (Exception) when (!cancellationToken.IsCancellationRequested)
        {
            sw.Stop();
            spinnerCts.Cancel();
            await AwaitSpinner(spinnerTask);

            ClearLine();
            Write(ConsoleColor.DarkRed, $"  ✗ {role} failed after {sw.Elapsed.TotalSeconds:F1}s");
            throw;
        }
    }

    public async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> messages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var colour = ColorFor(role);
        Write(colour, $"  → {role} streaming...");

        await foreach (var update in inner.GetStreamingResponseAsync(messages, options, cancellationToken))
            yield return update;

        Write(colour, $"  ✓ {role} stream complete");
    }

    public object? GetService(Type serviceType, object? serviceKey = null)
    {
        ArgumentNullException.ThrowIfNull(serviceType);
        return serviceKey is null && serviceType.IsInstanceOfType(this) ? this : inner.GetService(serviceType, serviceKey);
    }

    public void Dispose() => inner.Dispose();

    // ---------------------------------------------------------------- spinner --

    private static async Task RunSpinnerAsync(AgentRole role, ConsoleColor colour, Stopwatch sw, CancellationToken ct)
    {
        // Redirected output cannot be animated in place, so one static line stands in for
        // the whole wait instead of one line per frame.
        if (!CanAnimate)
        {
            Write(colour, $"  → {role} waiting for model...");
            return;
        }

        var frame = 0;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var elapsed = sw.Elapsed.TotalSeconds;
                var spinner = SpinnerFrames[frame % SpinnerFrames.Length];

                ConsoleOut.Spinner(colour, $"  {spinner} {role} waiting for model... {elapsed:F0}s");

                frame++;
                await Task.Delay(120, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) { /* expected */ }
    }

    private static async Task AwaitSpinner(Task spinnerTask)
    {
        try { await spinnerTask.ConfigureAwait(false); }
        catch (OperationCanceledException) { /* expected */ }
    }

    private static void ClearLine() => ConsoleOut.ClearSpinner();

    private static void Write(ConsoleColor colour, string text) => ConsoleOut.Line(colour, text);

    /// <summary>
    /// Runs a console operation, discarding any failure. A broken or redirected console
    /// must never propagate out of progress reporting and fail the agent's turn.
    /// </summary>
    private static void Swallow(Action consoleWrite)
    {
        try { consoleWrite(); }
        catch (IOException) { }
        catch (PlatformNotSupportedException) { }
    }
}
