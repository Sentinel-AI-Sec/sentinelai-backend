using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>
/// SEC-19: the full code→infra seam, from a Dockerfile + Terraform task definition to a
/// confidence-scored <c>runs-as</c> edge.
/// </summary>
public class CodeInfraSeamReaderTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();

    private readonly CodeInfraSeamReader _reader = new();

    private const string Dockerfile = """
        FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
        LABEL org.sentinelai.image="tinyapp/order"
        WORKDIR /app

        FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
        WORKDIR /src
        COPY . .
        RUN dotnet publish -c Release -o /app/publish

        FROM base AS final
        COPY --from=build /app/publish .
        ENTRYPOINT ["dotnet", "OrderService.dll"]
        """;

    private const string MatchingTaskDefTf = """
        resource "aws_ecs_task_definition" "order_task" {
          family = "order-task"
          container_definitions = jsonencode([
            {
              name  = "order"
              image = "123456789.dkr.ecr.us-east-1.amazonaws.com/tinyapp/order:latest"
            }
          ])
        }
        """;

    [Fact]
    public void Matching_normalized_names_produce_an_inferred_edge()
    {
        var result = _reader.Read(
            new CodeInfraSeamInput("src/OrderService/Dockerfile", Dockerfile, new Dictionary<string, string> { ["ecs.tf"] = MatchingTaskDefTf }),
            Tenant, Job);

        var edge = Assert.Single(result.Edges, e => e.Relation == "runs-as");
        Assert.Equal(Confidence.Inferred, edge.Confidence);
        Assert.Equal(NodeId.Code("OrderService"), edge.FromNodeKey);
        Assert.Equal(NodeId.Image("tinyapp/order"), edge.ToNodeKey);
        Assert.False(edge.ResolvedVariable);
    }

    /// <summary>
    /// SEC-20's addition: the traversable half of the seam. The image node records what was
    /// compared; this edge records where the code actually runs, which is the node the infra
    /// spine's <c>assumes</c> edge continues from.
    /// </summary>
    [Fact]
    public void A_match_also_joins_the_code_to_the_workload_it_is_deployed_into()
    {
        var result = _reader.Read(
            new CodeInfraSeamInput("src/OrderService/Dockerfile", Dockerfile, new Dictionary<string, string> { ["ecs.tf"] = MatchingTaskDefTf }),
            Tenant, Job);

        var edge = Assert.Single(result.Edges, e => e.Relation == "deployed-as");
        Assert.Equal(NodeId.Code("OrderService"), edge.FromNodeKey);
        Assert.Equal(NodeId.Task("order_task"), edge.ToNodeKey);

        // Same evidence as the runs-as edge beside it, so the same confidence — never stronger.
        Assert.Equal(Confidence.Inferred, edge.Confidence);
        Assert.Contains(result.Nodes, n => n.NodeKey == NodeId.Task("order_task") && n.NodeType == NodeType.Task);
    }

    /// <summary>
    /// The task node's key is built from the Terraform resource name, which is the same string
    /// <c>TerraformInfraSpineReader</c> canonicalizes. That equality is the entire join between
    /// this seam and the infra spine; if it drifts, the graph splits and no chain crosses.
    /// </summary>
    [Fact]
    public void The_task_node_key_matches_the_infra_spines_spelling()
    {
        const string spineTf = """
            resource "aws_ecs_task_definition" "order_task" {
              family = "order-task"
              container_definitions = jsonencode([{ name = "order", image = "tinyapp/order:1.0" }])
            }
            """;

        var seam = _reader.Read(
            new CodeInfraSeamInput("src/OrderService/Dockerfile", Dockerfile, new Dictionary<string, string> { ["ecs.tf"] = spineTf }),
            Tenant, Job);

        var spine = new TerraformInfraSpineReader(
            Microsoft.Extensions.Logging.Abstractions.NullLogger<TerraformInfraSpineReader>.Instance)
            .Read(new InfraSpineInput(DotText: null, new Dictionary<string, string> { ["ecs.tf"] = spineTf }), Tenant, Job);

        var seamTaskKey = Assert.Single(seam.Nodes, n => n.NodeType == NodeType.Task).NodeKey;
        var spineTaskKey = Assert.Single(spine.Nodes, n => n.NodeType == NodeType.Task).NodeKey;

        Assert.Equal(spineTaskKey, seamTaskKey);
    }

    [Fact]
    public void Full_chain_connects_end_to_end_on_the_fixtures_clean_join()
    {
        var result = _reader.Read(
            new CodeInfraSeamInput("src/OrderService/Dockerfile", Dockerfile, new Dictionary<string, string> { ["ecs.tf"] = MatchingTaskDefTf }),
            Tenant, Job);

        Assert.Contains(result.Nodes, n => n.NodeKey == NodeId.Code("OrderService"));
        Assert.Contains(result.Nodes, n => n.NodeKey == NodeId.Image("tinyapp/order") && n.NodeType == NodeType.Image);
    }

    [Fact]
    public void Both_sides_reference_an_image_but_names_disagree_produces_an_unresolved_edge_not_dropped()
    {
        const string mismatchedTaskDefTf = """
            resource "aws_ecs_task_definition" "order_task" {
              family = "order-task"
              container_definitions = jsonencode([
                { name = "order", image = "123456789.dkr.ecr.us-east-1.amazonaws.com/tinyapp/order-worker:latest" }
              ])
            }
            """;

        var result = _reader.Read(
            new CodeInfraSeamInput("src/OrderService/Dockerfile", Dockerfile, new Dictionary<string, string> { ["ecs.tf"] = mismatchedTaskDefTf }),
            Tenant, Job);

        Assert.All(result.Edges, e => Assert.Equal(Confidence.Unresolved, e.Confidence));
        Assert.Equal(["deployed-as", "runs-as"], result.Edges.Select(e => e.Relation).Order().ToList());
    }

    [Fact]
    public void A_variable_referenced_image_field_is_resolved_before_comparison()
    {
        const string tf = """
            variable "order_image" {
              default = "tinyapp/order"
            }

            resource "aws_ecs_task_definition" "order_task" {
              family = "order-task"
              container_definitions = jsonencode([
                { name = "order", image = "${var.order_image}:latest" }
              ])
            }
            """;

        var result = _reader.Read(
            new CodeInfraSeamInput("src/OrderService/Dockerfile", Dockerfile, new Dictionary<string, string> { ["ecs.tf"] = tf }),
            Tenant, Job);

        var edge = Assert.Single(result.Edges, e => e.Relation == "runs-as");
        Assert.Equal(Confidence.Inferred, edge.Confidence);
        Assert.True(edge.ResolvedVariable);
    }

    [Fact]
    public void No_image_label_in_the_dockerfile_produces_no_edge()
    {
        const string unlabeledDockerfile = """
            FROM mcr.microsoft.com/dotnet/aspnet:8.0
            ENTRYPOINT ["dotnet", "OrderService.dll"]
            """;

        var result = _reader.Read(
            new CodeInfraSeamInput("src/OrderService/Dockerfile", unlabeledDockerfile, new Dictionary<string, string> { ["ecs.tf"] = MatchingTaskDefTf }),
            Tenant, Job);

        Assert.Empty(result.Edges);
        Assert.Single(result.Nodes); // just the Code node
    }

    [Fact]
    public void No_task_definition_in_the_hcl_produces_no_edge()
    {
        var result = _reader.Read(
            new CodeInfraSeamInput("src/OrderService/Dockerfile", Dockerfile, new Dictionary<string, string>()),
            Tenant, Job);

        Assert.Empty(result.Edges);
        Assert.Single(result.Nodes);
    }
}
