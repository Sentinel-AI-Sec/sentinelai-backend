using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Graph;
using Xunit.Abstractions;

namespace SentinelAI.Integration.Tests.Scan.Graph;

public class ScratchMeasurementTests(ITestOutputHelper output)
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();
    private const string Locator = "fake://fixture";

    private const string Dockerfile = """
        FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
        LABEL org.sentinelai.image="tinyapp/order"
        WORKDIR /app
        EXPOSE 8080

        FROM base AS final
        ENTRYPOINT ["dotnet", "OrderApp.dll"]
        """;

    private const string LockFile = """
        {
          "version": 1,
          "dependencies": {
            "net8.0": {
              "Newtonsoft.Json": { "type": "Direct", "resolved": "12.0.1" }
            }
          }
        }
        """;

    private const string MainTf = """
        resource "aws_security_group" "order_svc_sg" {
          name = "order-svc-sg"
        }

        resource "aws_ecs_task_definition" "order_task" {
          family                   = "order-task"
          execution_role_arn       = aws_iam_role.order_task_role.arn
          task_role_arn            = aws_iam_role.order_task_role.arn

          container_definitions = jsonencode([
            {
              name  = "order-service"
              image = "registry.hub.docker.com/tinyapp/order:1.4.2"
            }
          ])
        }

        resource "aws_ecs_service" "order_service" {
          name            = "order-service"
          task_definition = aws_ecs_task_definition.order_task.arn

          network_configuration {
            security_groups = [aws_security_group.order_svc_sg.id]
          }
        }

        resource "aws_ecs_task_definition" "legacy_worker_task" {
          family             = "legacy-worker-task"
          execution_role_arn = aws_iam_role.legacy_worker_role.arn
          task_role_arn      = aws_iam_role.legacy_worker_role.arn

          container_definitions = jsonencode([
            {
              name  = "legacy-worker"
              image = var.legacy_worker_image
            }
          ])
        }
        """;

    private const string VariablesTf = """
        variable "legacy_worker_image" {
          description = "Image reference for the legacy worker task (ambiguous join, intentionally)"
          type        = string
          default     = "registry.internal.example.com/tinyapp-worker:latest"
        }
        """;

    private const string IamTf = """
        resource "aws_iam_role" "order_task_role" {
          name = "order-task-role"
        }

        resource "aws_iam_role_policy" "order_task_policy" {
          name = "order-task-s3-access"
          role = aws_iam_role.order_task_role.id

          policy = jsonencode({
            Statement = [
              {
                Effect   = "Allow"
                Action   = "s3:*"
                Resource = "*"
              }
            ]
          })
        }

        resource "aws_iam_role" "legacy_worker_role" {
          name = "legacy-worker-role"
        }
        """;

    private const string S3Tf = """
        resource "aws_s3_bucket" "customer_data" {
          bucket = "sentinelai-fixture-customer-data"
        }
        """;

    private static Dictionary<string, string> HclFiles() => new(StringComparer.OrdinalIgnoreCase)
    {
        ["graph-inputs/infra/main.tf"] = MainTf,
        ["graph-inputs/infra/variables.tf"] = VariablesTf,
        ["graph-inputs/infra/iam.tf"] = IamTf,
        ["graph-inputs/infra/s3.tf"] = S3Tf,
    };

    private static IReadOnlyList<Finding> FixtureFindings() =>
        new FindingUnifier().Unify(
        [
            Raw("osv", Layer.Dep, 4, "Newtonsoft.Json@12.0.1", "CVE-2024-21907 x"),
            Raw("roslyn", Layer.Code, 4, "src/OrderApp/Controllers/OrdersController.cs:41", "SCS0028 y"),
            Raw("checkov", Layer.Infra, 4, "infra/iam.tf:5", "CKV_AWS_290 z"),
        ]);

    private static Finding Raw(string tool, Layer layer, int severity, string location, string message) =>
        new()
        {
            Id = Guid.CreateVersion7(),
            TenantId = Tenant,
            ScanJobId = Job,
            SourceTool = tool,
            Layer = layer,
            Severity = severity,
            CheckId = message.Split(' ')[0],
            Location = location,
            Message = message,
        };

    [Fact]
    public async Task Measure()
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var hcl = HclFiles();

        await new InfraSpineWriter(
            new FakeGraphInputsStore { Files = hcl },
            new TerraformInfraSpineReader(NullLogger<TerraformInfraSpineReader>.Instance),
            unitOfWork, NullLogger<InfraSpineWriter>.Instance)
            .WriteAsync(Locator, Tenant, Job, CancellationToken.None);

        await new DepCodeSeamWriter(
            new DepCodeSeamReader(NullLogger<DepCodeSeamReader>.Instance),
            unitOfWork, NullLogger<DepCodeSeamWriter>.Instance)
            .WriteAsync("src/OrderApp/packages.lock.json", LockFile, Tenant, Job, CancellationToken.None);

        await new CodeInfraSeamWriter(new CodeInfraSeamReader(), unitOfWork, NullLogger<CodeInfraSeamWriter>.Instance)
            .WriteAsync("src/OrderApp/Dockerfile", Dockerfile, hcl, Tenant, Job, CancellationToken.None);

        await new RoleResourceSeamWriter(new RoleResourceSeamReader(), unitOfWork, NullLogger<RoleResourceSeamWriter>.Instance)
            .WriteAsync(hcl, Tenant, Job, CancellationToken.None);

        var chains = await new CandidateChainWriter(
            new FakeGraphInputsStore { Files = hcl },
            new TerraformFindingLocator(NullLogger<TerraformFindingLocator>.Instance),
            new GraphDecorator(NullLogger<GraphDecorator>.Instance),
            new ExploitChainTraverser(NullLogger<ExploitChainTraverser>.Instance),
            unitOfWork, NullLogger<CandidateChainWriter>.Instance)
            .WriteAsync(Locator, FixtureFindings(), Tenant, Job, CancellationToken.None);

        var nodes = unitOfWork.FakeRepository<GraphNode>().Added.ToDictionary(n => n.Id);
        var edges = unitOfWork.FakeRepository<GraphEdge>().Added;

        output.WriteLine($"NODES: {nodes.Count}  EDGES: {edges.Count}  CHAINS: {chains.Count}");
        foreach (var e in edges.Where(e => nodes.ContainsKey(e.FromNodeId) && nodes.ContainsKey(e.ToNodeId))
                     .Select(e => $"{nodes[e.FromNodeId].NodeKey} --{e.Relation}({e.Confidence})--> {nodes[e.ToNodeId].NodeKey}")
                     .Order(StringComparer.Ordinal))
        {
            output.WriteLine("  EDGE " + e);
        }

        var pairs = new HashSet<(Guid, Guid)>();
        foreach (var e in edges) pairs.Add((e.FromNodeId, e.ToNodeId));
        foreach (var (from, to) in pairs)
        {
            if (pairs.Contains((to, from)) && from.CompareTo(to) < 0)
                output.WriteLine($"  CONTRADICTION {nodes[from].NodeKey} <-> {nodes[to].NodeKey}");
        }

        foreach (var c in chains)
            output.WriteLine($"  CHAIN[{c.Priority}] min={c.MinConfidence} " + string.Join(" -> ", c.Hops.Select(h => h.Node.NodeKey)));

        Assert.True(false, "scratch");
    }
}
