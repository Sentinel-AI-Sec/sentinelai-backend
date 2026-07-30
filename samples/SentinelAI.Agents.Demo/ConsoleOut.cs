using SentinelAI.Domain.Models;

namespace SentinelAI.Agents.Demo;

/// <summary>
/// The single owner of stdout for the demo.
/// </summary>
/// <remarks>
/// Two writers used to share the console with no coordination: the spinner painted
/// <c>\r…</c> from a background task while the workflow event stream printed turns from
/// the run loop. Neither cleared the other, so live output interleaved into lines like
/// <c>"⠋ Blue waiting for model... 0s    N1 -> deserialization gadget chain"</c>.
/// Routing every write through here means a normal line always erases a live spinner
/// first, and no two writes overlap.
/// </remarks>
internal static class ConsoleOut
{
    private static readonly Lock Gate = new();

    /// <summary>True while a spinner frame occupies the current line.</summary>
    private static bool _spinnerVisible;

    /// <summary>True only when stdout is a real console that can be animated in place.</summary>
    private static bool CanAnimate => !Console.IsOutputRedirected;

    /// <summary>Writes a coloured line, erasing any spinner sitting on the current line.</summary>
    public static void Line(ConsoleColor colour, string text)
    {
        lock (Gate)
        {
            EraseSpinner();
            Swallow(() =>
            {
                var previous = Console.ForegroundColor;
                Console.ForegroundColor = colour;
                Console.WriteLine(text);
                Console.ForegroundColor = previous;
            });
        }
    }

    /// <summary>Writes an uncoloured line, erasing any spinner first.</summary>
    public static void Line(string text = "")
    {
        lock (Gate)
        {
            EraseSpinner();
            Swallow(() => Console.WriteLine(text));
        }
    }

    /// <summary>Paints one spinner frame in place. Never scrolls the buffer.</summary>
    public static void Spinner(ConsoleColor colour, string text)
    {
        if (!CanAnimate) return;

        lock (Gate)
        {
            Swallow(() =>
            {
                var previous = Console.ForegroundColor;
                Console.ForegroundColor = colour;
                Console.Write($"\r{text}");
                Console.ForegroundColor = previous;
                _spinnerVisible = true;
            });
        }
    }

    /// <summary>Removes a live spinner, leaving the cursor at the start of a clean line.</summary>
    public static void ClearSpinner()
    {
        lock (Gate) { EraseSpinner(); }
    }

    /// <summary>Caller must hold <see cref="Gate"/>.</summary>
    private static void EraseSpinner()
    {
        if (!_spinnerVisible) return;
        _spinnerVisible = false;

        if (!CanAnimate) return;

        // Console.WindowWidth throws on a redirected handle, hence the guarded call.
        Swallow(() => Console.Write($"\r{new string(' ', Math.Max(1, Console.WindowWidth - 1))}\r"));
    }

    /// <summary>
    /// Runs a console operation, discarding any failure. Progress reporting must never be
    /// able to fail a turn the model actually answered.
    /// </summary>
    private static void Swallow(Action action)
    {
        try { action(); }
        catch (IOException) { }
        catch (ArgumentOutOfRangeException) { }
    }
}
