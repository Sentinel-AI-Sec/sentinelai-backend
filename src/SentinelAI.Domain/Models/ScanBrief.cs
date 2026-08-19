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
    /// <remarks>
    /// <para><b>Three candidate paths, two of them false.</b> An earlier version had exactly one
    /// path, so Red asserted the same chain every round — there was nothing else to assert, and
    /// the adversarial dynamic the whole design rests on could not be observed. The debate
    /// converged in one round and only exercised the plumbing.</para>
    ///
    /// <para>The decisive detail is that the two false paths are <i>refutable</i>, not merely
    /// unconfirmable. The graph deliberately over-approximates the way a real extractor does —
    /// an IAM wildcard expands to an edge that an explicit Deny actually forbids — and the
    /// contradicting facts are supplied separately so Blue can find them. That is the
    /// false-positive reduction thesis in miniature: the graph over-approximates, and the
    /// adversary corrects it.</para>
    ///
    /// <para>Expected shape of a live debate: Red opens with the all-<c>CERTAIN</c> batch-worker
    /// chain because it looks strongest, Blue kills it on R1/R2, Red pivots to the api-service
    /// chain, and Blue confirms it with the image-name join left <c>UNRESOLVED</c>. Two rounds,
    /// ending in a convergence that carries an honest weakest-link tier — with one false
    /// positive eliminated on the way.</para>
    /// </remarks>
    /// <remarks>
    /// Node ids here are canonical <c>type:identifier</c> keys, spelled exactly as
    /// <see cref="ValueObjects.NodeId"/> would produce them. This fixture used to say
    /// <c>infra:ecs-task/api-service</c> and <c>iam-role:api-task-role</c> — neither of
    /// which is a real prefix, and the second is the exact <c>iam_role</c> versus
    /// <c>iam-role</c> mismatch SEC-03 exists to prevent. Since this text is what the agents
    /// learn the vocabulary from, Red would have asserted chains whose node ids could never
    /// be matched against the real graph once the graph builder lands.
    /// </remarks>
    private const string StubResourceGraph =
        """
        RESOURCE GRAPH
        Node ids are canonical: type:identifier, lower-case. Use them verbatim.
        More than one candidate path reaches the crown jewel. Not all of them survive validation.

        Findings:
          F1: commons-collections:3.2.1 CVE-2015-6420 CVSS-9.8 (CWE-502 deserialization gadget chain)
          F2: AppDataHandler.deserialize() — ObjectInputStream.readObject() on an untrusted S3 blob
          F3: LegacyImportController.upload() — ObjectInputStream.readObject() on an uploaded file
          F4: api-task-role inline policy grants s3:Get/PutObject on customer-data-bucket/*
          F5: batch-task-role inline policy contains an s3:* wildcard action

        Nodes: N1=pkg:commons-collections:3.2.1 | N2=code:appdatahandler.deserialize() | N3=code:legacyimportcontroller.upload() | N4=task:ecs-task/api-service | N5=task:ecs-task/batch-worker | N6=iam_role:api-task-role | N7=iam_role:batch-task-role | N8=s3:customer-data-bucket | N9=s3:build-artifacts

        N8 is the crown jewel: it holds customer PII. N9 holds build output only, no sensitive data.

        Edges (as emitted by the extractors — some over-approximate):
          N1→N2: used-by      CERTAIN   packages.lock.json pins 3.2.1; AppDataHandler imports InvokerTransformer
          N1→N3: used-by      CERTAIN   same lock file; LegacyImportController imports the same gadget class
          N2→N4: deployed-as  INFERRED  Dockerfile builds acme/api:latest; the api-service task definition
                                        references acme/api — a name convention, not a digest
          N3→N5: deployed-as  CERTAIN   the batch-worker task definition pins the image by digest sha256:9f2c…
          N4→N6: assumes      CERTAIN   api-service task definition taskRoleArn → api-task-role
          N5→N7: assumes      CERTAIN   batch-worker task definition taskRoleArn → batch-task-role
          N6→N8: can-access   CERTAIN   see F4
          N7→N8: can-access   CERTAIN   expanded from the s3:* wildcard in F5
          N7→N9: can-access   CERTAIN   see F5

        Contradicting evidence — these facts REFUTE a hop. They do not merely leave it unconfirmed:
          R1: batch-task-role's policy document carries an explicit Deny on
              arn:aws:s3:::customer-data-bucket/*. An explicit Deny overrides the s3:* Allow, so the
              N7→N8 edge above is a wildcard over-approximation and is wrong.
          R2: LegacyImportController.upload() is unreachable in production. appsettings.Production.json
              sets Features:LegacyImport=false and the route is never registered at startup, so the
              deserialization sink at N3 cannot be driven by an external caller.

        Unconfirmed evidence — this leaves a hop UNRESOLVED. It does NOT refute it:
          U1: the N2→N4 image-name join is consistent with the deployment but cannot be proved from
              the artifacts in this bundle — the tag is mutable and no digest was recorded.
        """;
}
