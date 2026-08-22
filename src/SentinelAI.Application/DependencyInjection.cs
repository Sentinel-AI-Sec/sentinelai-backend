using FluentValidation;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using SentinelAI.Application.Common.Behaviors;
using SentinelAI.Application.Features.Auth;

namespace SentinelAI.Application;


public static class DependencyInjection
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services)
    {
        services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(typeof(DependencyInjection).Assembly));
        services.AddValidatorsFromAssembly(typeof(DependencyInjection).Assembly);
        services.AddTransient(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));

        // After validation, and the order matters: registration order is execution order, so a
        // malformed submission is refused as a 400 before it can spend a customer's daily quota.
        services.AddTransient(typeof(IPipelineBehavior<,>), typeof(ScanQuotaBehavior<,>));

        services.AddScoped<AuthTokenFactory>();

        // SEC-14: the Normalize stage. Its IFindingExtractor set is supplied by Infrastructure.
        services.AddScoped<Features.Scan.Normalization.NormalizationPipeline>();
        services.AddScoped<Features.Scan.Normalization.NormalizedFindingWriter>();

        // SEC-15: the rule-mapping step inside that stage. Its IRuleMappingLookup is the SQL
        // implementation supplied by Infrastructure.
        services.AddScoped<Features.Scan.Normalization.RuleMappingResolver>();

        // SEC-16: the unify step that closes that stage. Pure — no port to supply.
        services.AddScoped<Features.Scan.Normalization.FindingUnifier>();

        // SEC-33: the ingress gate. Runs between normalization and everything that could send
        // content anywhere. Its ISecretScanner is supplied by Infrastructure, and IDebateEngine
        // is additionally wrapped there so the model boundary itself is guarded.
        services.AddScoped<Features.Scan.Security.IngressRedactionGate>();

        // SEC-34: the egress admission check the submit handler runs. Its IEgressPolicy and
        // IOutboundEndpointCatalog are supplied by Infrastructure, which owns configuration.
        services.AddScoped<Features.Scan.Security.EgressAdmission>();

        // SEC-17: the infra spine. Its IInfraSpineReader (the Terraform DOT/HCL reader) is
        // supplied by Infrastructure; this class owns the upsert against the DB.
        services.AddScoped<Features.Scan.Graph.InfraSpineWriter>();

        // SEC-18/19: the dep-code, role-resource, and code-infra seams. Each reader is supplied
        // by Infrastructure; each writer owns the upsert against the DB, same split as SEC-17.
        // Registered for consistency with that pattern, not because anything calls them yet —
        // see each writer's own doc remarks: no scan-job orchestration story exists yet for any
        // of these.
        services.AddScoped<Features.Scan.Graph.DepCodeSeamWriter>();
        services.AddScoped<Features.Scan.Graph.RoleResourceSeamWriter>();
        services.AddScoped<Features.Scan.Graph.CodeInfraSeamWriter>();

        // SEC-20: bounded candidate-chain generation over the graph those seams built. The
        // decorator and the traverser are pure; the writer owns the database and the bundle,
        // and takes its IInfraFindingLocator from Infrastructure.
        services.AddScoped<Features.Scan.Graph.GraphDecorator>();
        services.AddScoped<Features.Scan.Graph.ExploitChainTraverser>();
        services.AddScoped<Features.Scan.Graph.CandidateChainWriter>();

        // SEC-28: promotes the audit stage's outcome onto the top-priority chain row the graph
        // stage left at Candidate, so GET /v1/scans/{id}/chains reflects what Red and Blue
        // actually concluded rather than showing every chain untouched forever.
        services.AddScoped<Features.Scan.Graph.ChainOutcomeWriter>();
        services.AddScoped<Features.Scan.Audit.AuditIntegrityWriter>();

        // The graph stage as one callable unit — the four seam writers plus SEC-20 over one
        // ingested bundle. POST /v1/scans/{id}/graph is its only caller today; a queue-driven
        // worker takes it over when one exists.
        services.AddScoped<Features.Scan.Graph.GraphStagePipeline>();

        // SEC-21: the query the corpus is searched with. Pure — the retriever itself is the port.
        services.AddScoped<Features.Scan.Retrieval.RetrievalQueryBuilder>();

        // SEC-45: the walking skeleton. Every stage below is pure except the two ports it
        // composes — IKnowledgeRetriever and IDebateEngine — which Infrastructure supplies.
        services.AddScoped<Features.Scan.Graph.GraphSeeder>();
        services.AddScoped<Features.Scan.Graph.ScanBriefRenderer>();
        services.AddScoped<Features.Scan.Reporting.ReportBuilder>();
        services.AddScoped<Features.Scan.ThinSlice.ThinSlicePipeline>();

        // SEC-35: retention. The pipeline's last stage — the bundle is deleted and the report
        // is kept only on opt-in — so "we delete your data" happens by default rather than
        // when someone remembers to call the purge endpoint.
        services.AddScoped<Abstractions.IScanRetentionPolicy, Features.Scan.Retention.ScanRetentionPolicy>();

        // SEC-46: the stages above, in order, driven by the worker rather than by hand. Scoped
        // like everything it composes, and resolved once per claimed job — the worker gives each
        // run a scope of its own so the tenant it assumes cannot outlive the job it was claimed
        // for. Registered here rather than in Infrastructure because it is an Application service
        // that happens to have a background caller; the worker depends on this, not the reverse.
        services.AddScoped<Features.Scan.Orchestration.ScanPipelineRunner>();

        return services;
    }
}
