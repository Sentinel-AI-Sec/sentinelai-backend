namespace SentinelAI.Application.Abstractions;

/// <summary>
/// A debate engine that wraps another one, and will say what it wraps.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="IDebateEngine"/> is deliberately decorated more than once — SEC-33 redacts the brief
/// on the way out, SEC-50 checks edge integrity on the way back — and each new guard goes on the
/// outside. That is the right shape, and it broke the test pinning the previous one:
/// <c>IngressRedactionWiringTests</c> asserted the resolved engine's <em>exact</em> type, so
/// wrapping it in SEC-50's checker turned a still-correct guarantee into a red build.
/// </para>
/// <para>
/// The guarantee those tests care about is "this guard is in the chain and cannot be bypassed",
/// not "this guard is outermost". Exposing <see cref="Inner"/> lets them assert the real thing, so
/// the next decorator is not a breaking change to every wiring test written before it.
/// </para>
/// </remarks>
public interface IDecoratingDebateEngine : IDebateEngine
{
    /// <summary>The engine this one wraps.</summary>
    IDebateEngine Inner { get; }
}

/// <summary>Walks a decorated <see cref="IDebateEngine"/> chain.</summary>
public static class DebateEngineChain
{
    /// <summary>The engine and everything it wraps, outermost first.</summary>
    public static IEnumerable<IDebateEngine> Unwrap(this IDebateEngine engine)
    {
        ArgumentNullException.ThrowIfNull(engine);

        for (var current = engine; current is not null;
             current = (current as IDecoratingDebateEngine)?.Inner)
        {
            yield return current;
        }
    }

    /// <summary>True when <typeparamref name="T"/> appears anywhere in the chain.</summary>
    public static bool Wraps<T>(this IDebateEngine engine) where T : IDebateEngine =>
        engine.Unwrap().OfType<T>().Any();
}
