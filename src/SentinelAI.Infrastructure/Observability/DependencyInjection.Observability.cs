using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry.Exporter;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

namespace SentinelAI.Infrastructure.Observability;

/// <summary>
/// SEC-36: registers the OTLP trace exporter, when — and only when — one is configured.
/// </summary>
/// <remarks>
/// <para>
/// <b>Unconfigured registers nothing at all.</b> Not a disabled exporter, not a no-op processor:
/// nothing. With no listener subscribed to the source, <c>ActivitySource.StartActivity</c>
/// returns null and the instrumentation in the executors costs one null check per turn. That is
/// the same argument as the <c>Scripted</c> provider default — a fresh clone and a CI run must
/// work with no credentials and no collector — and it is why this returns early rather than
/// registering a pipeline that exports to nowhere.
/// </para>
/// <para>
/// <b>Traces only.</b> Metrics and logs are a different ticket and a different backend
/// concern; adding them here because the package supports them would export three signals a
/// deployment did not ask for, to an endpoint sized for one.
/// </para>
/// </remarks>
public static class ObservabilityDependencyInjection
{
    public static IServiceCollection AddSentinelTelemetry(
        this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        var options = TracingOptionsLoader.Load(configuration);

        // Registered whether or not tracing is on, because the debate engine reads
        // CaptureContent from it and would otherwise need its own copy of the loader.
        services.AddSingleton(options);

        if (!options.IsEnabled) return services;

        var headers = options.ComposeHeaders();

        services
            .AddOpenTelemetry()
            .ConfigureResource(resource => resource
                .AddService(serviceName: options.ServiceName)
                .AddAttributes([new KeyValuePair<string, object>("sentinelai.component", "backend")]))
            .WithTracing(tracing =>
            {
                tracing.AddSource(DebateTracing.SourceName);

                // The framework's own sources. They emit only when a chat client is wrapped in
                // the Agent Framework's OpenTelemetry decorator, which this project does not do
                // — so today these produce nothing. Subscribed anyway: the cost is zero, and the
                // alternative is a deployment that turns the decorator on later and silently
                // exports nothing while believing it is instrumented.
                foreach (var source in DebateTracing.FrameworkSourceNames) tracing.AddSource(source);

                tracing.AddOtlpExporter(exporter =>
                {
                    exporter.Endpoint = new Uri(options.OtlpEndpoint!);

                    // HTTP/protobuf rather than gRPC. Langfuse's OTLP ingest is HTTP-only, and
                    // the endpoint people are given is a full /v1/traces path — configuring gRPC
                    // against it fails at connect time with an error that reads like a network
                    // problem rather than a protocol mismatch.
                    exporter.Protocol = OtlpExportProtocol.HttpProtobuf;

                    if (headers is not null) exporter.Headers = headers;
                });
            });

        return services;
    }
}
