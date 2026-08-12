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

        var edge = Assert.Single(result.Edges);
        Assert.Equal(Confidence.Inferred, edge.Confidence);
        Assert.Equal("runs-as", edge.Relation);
        Assert.Equal(NodeId.Code("OrderService"), edge.FromNodeKey);
        Assert.Equal(NodeId.Image("tinyapp/order"), edge.ToNodeKey);
        Assert.False(edge.ResolvedVariable);
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

        var edge = Assert.Single(result.Edges);
        Assert.Equal(Confidence.Unresolved, edge.Confidence);
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

        var edge = Assert.Single(result.Edges);
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
