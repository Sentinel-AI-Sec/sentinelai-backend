using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelAI.Application.Features.Scan.Graph;
using SentinelAI.Application.Features.Scan.Normalization;
using SentinelAI.Domain.Enums;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.ValueObjects;
using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Integration.Tests.Scan.Graph;

/// <summary>
/// SEC-20's acceptance criterion, end to end: the committed fixture's flagship chain appears
/// among the bounded candidates, with the confidence of its weakest join.
/// </summary>
/// <remarks>
/// <para>
/// Every stage here is the real one — the four seam readers and writers, the real
/// <see cref="FindingUnifier"/> that builds node references, the real
/// <see cref="TerraformFindingLocator"/>, the real decorator and traverser. Only the database
/// and the bundle store are fakes. That matters because the failure this test exists to catch
/// is not in any one of those stages; it is in the joins between them, where two stages spell
/// the same node two different ways and the graph splits into islands with nothing erroring.
/// </para>
/// <para>
/// The Terraform, the Dockerfile and the scanner locations below are the fixture's own
/// (<c>sentinelai-fixtures</c>), trimmed to the blocks that carry the chain. Rewriting them to
/// something tidier would make this test pass on a graph the product never sees.
/// </para>
/// <para>
/// <b>These are copies, and a copy can drift from what it copies.</b> For one sprint this file's
/// Dockerfile carried <c>LABEL org.sentinelai.image</c> while the fixture's did not: this test
/// asserted the flagship chain end to end and passed, while the committed fixture produced seven
/// two-node candidates and no flagship. The label is in the fixture now, but the hazard is
/// structural — nothing here reads a fixture file from disk, so every constant below is a
/// snapshot that only a human keeps in step. Prefer adding a from-disk assertion over adding a
/// constant when covering something new.
/// </para>
/// </remarks>
public class FlagshipChainTests
{
    private static readonly Guid Tenant = Guid.NewGuid();
    private static readonly Guid Job = Guid.NewGuid();
    private const string Locator = "fake://fixture";

    /// <summary>
    /// The fixture's Dockerfile is at the repository root, so which project it builds is the
    /// caller's decision — no ticket owns Dockerfile-to-project attribution yet (see
    /// <c>ProvisionalCodeNodeResolver</c>'s remarks). A project-scoped call is what a real
    /// pipeline would make, and it is what keeps the code node the same one the lock file
    /// produced.
    /// </summary>
    private const string ProjectDockerfilePath = "src/OrderApp/Dockerfile";
    private const string ProjectLockFilePath = "src/OrderApp/packages.lock.json";

    private static readonly string PackageKey = NodeId.Package("newtonsoft.json");
    private static readonly string CodeKey = NodeId.Code("OrderApp");
    private static readonly string TaskKey = NodeId.Task("order_task");
    private static readonly string RoleKey = NodeId.Role("order_task_role");
    private static readonly string BucketKey = NodeId.Resource("customer_data");

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
              "Newtonsoft.Json": {
                "type": "Direct",
                "requested": "[12.0.1, )",
                "resolved": "12.0.1"
              }
            }
          }
        }
        """;

    private const string MainTf = """
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
        """;

    /// <summary>
    /// The fixture's <c>infra/iam.tf</c>, verbatim down to the comment lines, because Checkov
    /// reports the flagship IAM finding at <b>line 25</b> and that number is only line 25 in this
    /// exact text. Trimming the comments would silently move the policy block and the
    /// line-to-resource join under test would be testing a file the scanner never saw.
    /// </summary>
    private const string IamTf = """
        # --- Flagship role: reachable from order-task, over-permissioned --------

        resource "aws_iam_role" "order_task_role" {
          name = "order-task-role"

          assume_role_policy = jsonencode({
            Version = "2012-10-17"
            Statement = [
              {
                Action = "sts:AssumeRole"
                Effect = "Allow"
                Principal = {
                  Service = "ecs-tasks.amazonaws.com"
                }
              }
            ]
          })
        }

        # VULN (INFRA-01 - flagship): wildcard action + wildcard resource.
        # Checkov: CKV_AWS_* (IAM policy allows * action / * resource)
        # rule_mappings resolves this check_id -> CWE-284 (Improper Access Control).
        # This is the edge order_task_role.arn --can-access--> S3 customer-data,
        # confidence = "certain" (explicit inline policy statement).
        resource "aws_iam_role_policy" "order_task_policy" {
          name = "order-task-s3-access"
          role = aws_iam_role.order_task_role.id

          policy = jsonencode({
            Version = "2012-10-17"
            Statement = [
              {
                Effect   = "Allow"
                Action   = "s3:*"
                Resource = "*"
              }
            ]
          })
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
        ["graph-inputs/infra/iam.tf"] = IamTf,
        ["graph-inputs/infra/s3.tf"] = S3Tf,
    };

    /// <summary>
    /// The three findings that seed the chain, spelled the way their scanners spell them:
    /// OSV names a package coordinate, Roslyn a source file, Checkov a Terraform file and line.
    /// The real unifier turns them into node references — the point being that none of those
    /// references equals a graph node key, which is exactly the gap the decorator closes.
    /// </summary>
    private static IReadOnlyList<Finding> FixtureFindings() =>
        new FindingUnifier().Unify(
        [
            Raw("osv", Layer.Dep, severity: 4, "Newtonsoft.Json@12.0.1",
                "CVE-2024-21907 improper handling of exceptional conditions"),
            Raw("roslyn", Layer.Code, severity: 4, "src/OrderApp/Controllers/OrdersController.cs:41",
                "SCS0028 deserialization of untrusted data"),
            Raw("checkov", Layer.Infra, severity: 4, "infra/iam.tf:25",
                "CKV_AWS_290 IAM policy allows write access without constraints"),
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

    /// <summary>
    /// Runs the four seam writers over the fixture, exactly as a scan pipeline would once one
    /// exists, and returns the unit of work holding the graph they built.
    /// </summary>
    private static async Task<FakeUnitOfWork> BuildGraphAsync()
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var hcl = HclFiles();
        var store = new FakeGraphInputsStore { Files = hcl };

        await new InfraSpineWriter(
            store,
            new TerraformInfraSpineReader(NullLogger<TerraformInfraSpineReader>.Instance),
            unitOfWork,
            NullLogger<InfraSpineWriter>.Instance)
            .WriteAsync(Locator, Tenant, Job, CancellationToken.None);

        await new DepCodeSeamWriter(
            new DepCodeSeamReader(NullLogger<DepCodeSeamReader>.Instance),
            unitOfWork,
            NullLogger<DepCodeSeamWriter>.Instance)
            .WriteAsync(ProjectLockFilePath, LockFile, Tenant, Job, CancellationToken.None);

        await new CodeInfraSeamWriter(
            new CodeInfraSeamReader(), unitOfWork, NullLogger<CodeInfraSeamWriter>.Instance)
            .WriteAsync(ProjectDockerfilePath, Dockerfile, hcl, Tenant, Job, CancellationToken.None);

        await new RoleResourceSeamWriter(
            new RoleResourceSeamReader(), unitOfWork, NullLogger<RoleResourceSeamWriter>.Instance)
            .WriteAsync(hcl, Tenant, Job, CancellationToken.None);

        return unitOfWork;
    }

    private static async Task<IReadOnlyList<CandidateChain>> TraverseFixtureAsync(FakeUnitOfWork unitOfWork) =>
        await new CandidateChainWriter(
            new FakeGraphInputsStore { Files = HclFiles() },
            new TerraformFindingLocator(NullLogger<TerraformFindingLocator>.Instance),
            new GraphDecorator(NullLogger<GraphDecorator>.Instance),
            new ExploitChainTraverser(NullLogger<ExploitChainTraverser>.Instance),
            unitOfWork,
            NullLogger<CandidateChainWriter>.Instance)
            .WriteAsync(Locator, FixtureFindings(), Tenant, Job, CancellationToken.None);

    /// <summary>
    /// The graph the four seams build has to actually connect before any chain can exist. Asserted
    /// separately from the traversal so a broken join names itself instead of surfacing as
    /// "no candidates".
    /// </summary>
    [Fact]
    public async Task The_four_seams_build_one_connected_graph()
    {
        var unitOfWork = await BuildGraphAsync();

        var nodes = unitOfWork.FakeRepository<GraphNode>().Added.ToDictionary(n => n.NodeKey, StringComparer.Ordinal);
        var edges = unitOfWork.FakeRepository<GraphEdge>().Added;

        Assert.All(
            new[] { PackageKey, CodeKey, TaskKey, RoleKey, BucketKey },
            key => Assert.Contains(key, nodes.Keys));

        static bool Joins(IEnumerable<GraphEdge> edges, GraphNode from, GraphNode to) =>
            edges.Any(e => e.FromNodeId == from.Id && e.ToNodeId == to.Id);

        Assert.True(Joins(edges, nodes[PackageKey], nodes[CodeKey]), "dep→code");
        Assert.True(Joins(edges, nodes[CodeKey], nodes[TaskKey]), "code→infra");
        Assert.True(Joins(edges, nodes[TaskKey], nodes[RoleKey]), "task→role");
        Assert.True(Joins(edges, nodes[RoleKey], nodes[BucketKey]), "role→resource");
    }

    /// <summary>The acceptance criterion itself.</summary>
    [Fact]
    public async Task The_flagship_chain_appears_among_the_candidates()
    {
        var candidates = await TraverseFixtureAsync(await BuildGraphAsync());

        var flagship = Assert.Single(
            candidates,
            c => Path(c) == $"{PackageKey} -> {CodeKey} -> {TaskKey} -> {RoleKey} -> {BucketKey}");

        Assert.Equal(4, flagship.HopCount);
        Assert.Equal(ChainStatusCandidateHopOrders, flagship.Hops.Select(h => h.Order).ToList());
    }

    private static readonly int[] ChainStatusCandidateHopOrders = [0, 1, 2, 3, 4];

    /// <summary>
    /// The image-name join is a convention, not a proof, so the whole chain inherits
    /// <see cref="Confidence.Inferred"/> — however certain the lock file, the role attachment
    /// and the IAM grant are. Reporting this chain as confirmed is the false positive the
    /// weakest-link rule exists to prevent.
    /// </summary>
    [Fact]
    public async Task The_flagship_chain_carries_the_confidence_of_its_weakest_join()
    {
        var candidates = await TraverseFixtureAsync(await BuildGraphAsync());

        var flagship = candidates.Single(c => c.Seed.Node.NodeKey == PackageKey && c.Target.Node.NodeKey == BucketKey);

        Assert.Equal(Confidence.Inferred, flagship.MinConfidence);
        Assert.Equal(
            Confidence.Inferred,
            Assert.Single(flagship.Hops.Skip(1), h => h.EdgeFromPrevious!.Relation == "deployed-as")
                .EdgeFromPrevious!.Confidence);
        Assert.All(
            flagship.Hops.Skip(1).Where(h => h.EdgeFromPrevious!.Relation != "deployed-as"),
            h => Assert.Equal(Confidence.Certain, h.EdgeFromPrevious!.Confidence));
    }

    /// <summary>
    /// The seeds are the three findings, each placed on a structural node by a different rule:
    /// version-stripping, project-directory matching, and Terraform block location. If any one
    /// of them regresses, the node it should have made hot stops seeding chains.
    /// </summary>
    [Fact]
    public async Task All_three_scanner_layers_land_on_the_structural_graph()
    {
        var unitOfWork = await BuildGraphAsync();
        await TraverseFixtureAsync(unitOfWork);

        var hot = unitOfWork.FakeRepository<GraphNode>().Added
            .Where(n => n.IsHot)
            .Select(n => n.NodeKey)
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.Equal([CodeKey, RoleKey, PackageKey], hot.Order(StringComparer.Ordinal).ToList());
    }

    /// <summary>
    /// The persisted rows, not just the returned objects. A chain nobody can read back is not a
    /// chain the next stage can use.
    /// </summary>
    [Fact]
    public async Task The_flagship_chain_is_persisted_with_its_hops()
    {
        var unitOfWork = await BuildGraphAsync();
        var candidates = await TraverseFixtureAsync(unitOfWork);

        var flagship = candidates.Single(c => c.Seed.Node.NodeKey == PackageKey && c.Target.Node.NodeKey == BucketKey);
        var chain = Assert.Single(
            unitOfWork.FakeRepository<Chain>().Added,
            c => c.Priority == flagship.Priority && c.HopCount == 4 && c.MinConfidence == Confidence.Inferred);

        var hops = unitOfWork.FakeRepository<ChainHop>().Added
            .Where(h => h.ChainId == chain.Id)
            .OrderBy(h => h.HopOrder)
            .ToList();

        Assert.Equal(5, hops.Count);
        Assert.Equal(ChainStatus.Candidate, chain.Status);
        Assert.Null(hops[0].EdgeId);

        // The package, the code and the role were reported on; the task definition and the
        // bucket were not, and that is a hop with no finding rather than a broken chain.
        Assert.Equal(3, hops.Count(h => h.FindingId is not null));
    }

    /// <summary>
    /// The fixture's deliberate distractor: <c>legacy_worker_task</c>'s image comes from a
    /// variable that does not normalize to any Dockerfile here. The join is recorded, not
    /// dropped, so any chain through it is <c>Unresolved</c> — "potential chain, unverified
    /// join", never a confirmed result.
    /// </summary>
    /// <remarks>
    /// The image below is written <c>image = var.legacy_worker_image</c> — bare, exactly as
    /// <c>sentinelai-fixtures/infra/main.tf</c> writes it. It used to be quoted here
    /// (<c>"${var.legacy_worker_image}"</c>), and that one pair of quotes is the whole of finding
    /// 19-B: the extractor's regex accepted only quoted values, so this test matched and passed
    /// while the real fixture's legacy task was dropped from the extractor's output entirely —
    /// not recorded as unresolved, simply gone. The tier this test exists to prove was
    /// unreachable in production for a sprint, and the copy is why nobody could see it.
    /// </remarks>
    [Fact]
    public async Task The_deliberately_ambiguous_join_produces_an_unresolved_chain_not_a_missing_one()
    {
        var unitOfWork = new FakeUnitOfWork(new FakeScanJobRepository());
        var hcl = HclFiles();
        hcl["graph-inputs/infra/legacy.tf"] = """
            variable "legacy_worker_image" {
              default = "registry.internal.example.com/tinyapp-worker:latest"
            }

            resource "aws_ecs_task_definition" "legacy_worker_task" {
              family        = "legacy-worker-task"
              task_role_arn = aws_iam_role.legacy_worker_role.arn

              container_definitions = jsonencode([
                { name = "legacy-worker", image = var.legacy_worker_image }
              ])
            }

            resource "aws_iam_role" "legacy_worker_role" {
              name = "legacy-worker-role"
            }
            """;

        await new CodeInfraSeamWriter(new CodeInfraSeamReader(), unitOfWork, NullLogger<CodeInfraSeamWriter>.Instance)
            .WriteAsync(ProjectDockerfilePath, Dockerfile, hcl, Tenant, Job, CancellationToken.None);

        await new InfraSpineWriter(
            new FakeGraphInputsStore { Files = hcl },
            new TerraformInfraSpineReader(NullLogger<TerraformInfraSpineReader>.Instance),
            unitOfWork,
            NullLogger<InfraSpineWriter>.Instance)
            .WriteAsync(Locator, Tenant, Job, CancellationToken.None);

        var candidates = await new CandidateChainWriter(
            new FakeGraphInputsStore { Files = hcl },
            new TerraformFindingLocator(NullLogger<TerraformFindingLocator>.Instance),
            new GraphDecorator(NullLogger<GraphDecorator>.Instance),
            new ExploitChainTraverser(NullLogger<ExploitChainTraverser>.Instance),
            unitOfWork,
            NullLogger<CandidateChainWriter>.Instance)
            .WriteAsync(Locator, FixtureFindings(), Tenant, Job, CancellationToken.None);

        var legacy = Assert.Single(
            candidates, c => c.Hops.Any(h => h.Node.NodeKey == NodeId.Task("legacy_worker_task")));

        Assert.Equal(Confidence.Unresolved, legacy.MinConfidence);
        Assert.Equal(NodeId.Role("legacy_worker_role"), legacy.Target.Node.NodeKey);
    }

    /// <summary>
    /// The graph never stores a task↔role pair in both directions, and therefore no candidate can
    /// walk the backwards one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The spine reverses every Terraform dependency, which for <c>task depends on role</c>
    /// yields <c>role → task</c> — a build-order fact flipped into something that reads as an
    /// attacker move and is not one. <c>TaskDefinitionRoleExtractor</c> separately emits
    /// <c>task --assumes--&gt; role</c>, which is the real move. Measured on the fixture, both
    /// used to be stored, both <see cref="Confidence.Certain"/>, making a two-node cycle out of
    /// the hop the flagship chain runs through.
    /// </para>
    /// <para>
    /// This asserts the pair is now claimed once, not filtered later. An earlier version of this
    /// test asserted the opposite — that the reversed edge <em>is</em> stored and traversal
    /// simply declines to walk it — which left the contradiction in the database for every
    /// consumer that is not the traverser.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task The_task_role_pair_is_stored_in_one_direction_only()
    {
        var unitOfWork = await BuildGraphAsync();
        var candidates = await TraverseFixtureAsync(unitOfWork);

        var nodes = unitOfWork.FakeRepository<GraphNode>().Added.ToDictionary(n => n.NodeKey, StringComparer.Ordinal);
        var edges = unitOfWork.FakeRepository<GraphEdge>().Added;

        Assert.Contains(edges, e => e.FromNodeId == nodes[TaskKey].Id && e.ToNodeId == nodes[RoleKey].Id);

        Assert.DoesNotContain(edges, e => e.FromNodeId == nodes[RoleKey].Id && e.ToNodeId == nodes[TaskKey].Id);

        // No pair anywhere in the graph is joined in both directions.
        var pairs = edges.Select(e => (e.FromNodeId, e.ToNodeId)).ToHashSet();
        Assert.DoesNotContain(pairs, p => pairs.Contains((p.ToNodeId, p.FromNodeId)));

        // And the traversal, unsurprisingly, cannot walk an edge that does not exist.
        Assert.All(candidates, c => Assert.DoesNotContain(
            c.Hops.Skip(1),
            h => h.EdgeFromPrevious!.FromNodeId == nodes[RoleKey].Id
                 && h.EdgeFromPrevious.ToNodeId == nodes[TaskKey].Id));
    }

    private static string Path(CandidateChain chain) =>
        string.Join(" -> ", chain.Hops.Select(h => h.Node.NodeKey));
}
