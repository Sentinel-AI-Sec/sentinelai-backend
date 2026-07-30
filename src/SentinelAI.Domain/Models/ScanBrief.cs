namespace SentinelAI.Domain.Models;

/// <summary>
/// The brief handed to the debate: what the agents are reasoning about.
/// </summary>
/// <remarks>
/// <see cref="Context"/> is a rendered resource graph rather than the typed
/// <see cref="GraphNode"/>/<see cref="GraphEdge"/> set, because the agents consume it as
/// prompt text. When the real graph builder lands it produces the typed model and a
/// renderer fills this field — the debate itself does not change.
/// </remarks>
public sealed record ScanBrief(string ScanJobId, string Context)
{
    public static ScanBrief Stub(string scanJobId = "stub-scan") =>
        new(scanJobId, StubResourceGraph);

    /// <summary>
    /// A concrete three-layer resource graph that models the fixture described in AID-01.
    /// Gives Red real nodes and directed edges to chain from, and Blue ground truth to
    /// validate against — so neither agent hallucinates or asks for missing context.
    /// </summary>
    private const string StubResourceGraph =
        """
        RESOURCE GRAPH
        Findings:
          F1: commons-collections:3.2.1 CVE-2015-6420 CVSS-9.8 (CWE-502 deserialization)
          F2: AppDataHandler.deserialize() — ObjectInputStream.readObject() on untrusted S3 blob

        Nodes: N1=pkg:commons-collections:3.2.1 | N2=code:AppDataHandler.deserialize() | N3=infra:ecs-task/api-service | N4=iam-role:api-task-role | N5=s3:customer-data-bucket(PII)

        Edges:
          N1→N2: lock file pins 3.2.1, code imports InvokerTransformer
          N2→N3: Dockerfile base-image:latest → ecs-task/api-service (INFERRED image-name join)
          N3→N4: task def taskRoleArn → api-task-role
          N4→N5: IAM policy grants s3:Get/PutObject on customer-data-bucket/*

        Note: N2→N3 is convention-based (INFERRED), all others confirmed.
        """;
}
