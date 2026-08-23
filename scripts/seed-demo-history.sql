-- Seeds scan history for the demo tenant by REPLAYING the one real scan.
--
-- Nothing here is invented. Every finding, graph node, edge, chain and hop is copied from scan
-- 01a024b6-ad40-7ec4-b20e-c5cb76faf3d4 — a genuine pipeline run over sentinelai-fixtures that
-- produced 86 findings, 69 nodes and 48 chains. What is synthesised is only the *envelope*: new
-- scan ids, commit shas, PR refs and timestamps, so the history list has more than one row.
--
-- Why replay rather than fabricate: a console for a security product must not be demonstrated on
-- results a scanner never produced. Copying a real run means every chain a reader opens is one the
-- pipeline actually found, with the confidence tiers it actually assigned.
--
-- Every row this creates is tagged: seeded scans use PrRef 'refs/pull/9xx/merge'. To remove them:
--
--   DELETE FROM ScanJobs WHERE PrRef LIKE 'refs/pull/9%/merge' AND TenantId = '<tenant>';
--
-- (children cascade, except Chains/ChainHops/GraphEdges which are Restrict — see the DELETE block
-- at the foot of this file for the full teardown in dependency order.)
--
-- Safe to run more than once: it deletes its own previous output first.

SET NOCOUNT ON;
SET XACT_ABORT ON;

-- The real scan being replayed. Do not change unless a newer genuine run exists.
DECLARE @src     UNIQUEIDENTIFIER = '01a024b6-ad40-7ec4-b20e-c5cb76faf3d4';

-- Who gets the history. Override with sqlcmd -v tenant="..." project="..." to seed another
-- tenant; the defaults are the account the console is normally demonstrated from.
DECLARE @tenant  UNIQUEIDENTIFIER = TRY_CONVERT(UNIQUEIDENTIFIER, '$(tenant)');
DECLARE @project UNIQUEIDENTIFIER = TRY_CONVERT(UNIQUEIDENTIFIER, '$(project)');

IF @tenant IS NULL OR @project IS NULL
BEGIN
    RAISERROR('Pass -v tenant="<guid>" project="<guid>".', 16, 1);
    RETURN;
END

IF NOT EXISTS (SELECT 1 FROM ScanJobs WHERE Id = @src)
BEGIN
    RAISERROR('Source scan not found — nothing to replay.', 16, 1);
    RETURN;
END

BEGIN TRANSACTION;

-- ---- Teardown of any previous run of this script -------------------------------------------
-- Children first: ChainHop -> Finding/GraphEdge and GraphEdge -> GraphNode are Restrict.
DECLARE @old TABLE (Id UNIQUEIDENTIFIER);
INSERT INTO @old SELECT Id FROM ScanJobs WHERE PrRef LIKE 'refs/pull/9%/merge' AND TenantId = @tenant;

DELETE FROM ChainHops   WHERE ChainId IN (SELECT Id FROM Chains WHERE ScanJobId IN (SELECT Id FROM @old));
DELETE FROM Chains      WHERE ScanJobId IN (SELECT Id FROM @old);
DELETE FROM GraphEdges  WHERE ScanJobId IN (SELECT Id FROM @old);
DELETE FROM GraphNodes  WHERE ScanJobId IN (SELECT Id FROM @old);
DELETE FROM Reports     WHERE ScanJobId IN (SELECT Id FROM @old);
DELETE FROM Findings    WHERE ScanJobId IN (SELECT Id FROM @old);
DELETE FROM ScanJobs    WHERE Id IN (SELECT Id FROM @old);

-- ---- The scans to create --------------------------------------------------------------------
-- Chosen to exercise every state the history screen renders: the status chips, a failure reason,
-- an in-flight run, and — deliberately — a completed scan with NO report, because retention is
-- opt-in and "no report" is the ordinary case rather than a fault.
--
-- NOTE: do not seed a row in 'Queued'. SEC-46's worker polls for queued jobs and will claim one
-- within seconds, then fail it at the normalize stage with "this job has no stored bundle" —
-- because a replayed scan has no tarball behind it. The row is real enough for the read API and
-- not real enough for the pipeline, and the worker is right to say so.
DECLARE @scans TABLE (
    NewId     UNIQUEIDENTIFIER,
    HoursAgo  INT,
    Status    NVARCHAR(50),
    Stage     NVARCHAR(50),
    Sha       NVARCHAR(100),
    Pr        NVARCHAR(200),
    Retain    BIT,
    Clone     BIT,
    Failure   NVARCHAR(500),
    RanMins   INT
);

INSERT INTO @scans (NewId, HoursAgo, Status, Stage, Sha, Pr, Retain, Clone, Failure, RanMins)
VALUES
    (NEWID(), 150, 'Completed', 'Report',   '7c41f9a2e5b83d1067ea4c2b9f5d380a1e6c74bb', 'refs/pull/901/merge', 1, 1, NULL, 6),
    (NEWID(), 121, 'Failed',    'Graph',    '2f8ad0c47b1e95360af2d8e173c9b40567edc21a', 'refs/pull/902/merge', 0, 0,
        'graph stage: terraform-graph.dot was absent from the bundle, so no infra spine could be built', 2),
    (NEWID(),  96, 'Completed', 'Report',   'b93e1d7melded0000000000000000000000000000', 'refs/pull/903/merge', 0, 1, NULL, 5),
    (NEWID(),  49, 'Completed', 'Report',   'e04c7b21a9f6d385c1b0e29a7f43d6058cb1927e', 'refs/pull/904/merge', 1, 1, NULL, 5),
    (NEWID(),  20, 'Running',   'Debate',   'd1a6f30b8c25e947a0fb3d16850c2e79b4af6d33', 'refs/pull/905/merge', 1, 0, NULL, NULL),
    (NEWID(),   2, 'Completed', 'Report',   '5be9207caf184d63b0e5713a2c8fd90e64137aa8', 'refs/pull/906/merge', 1, 1, NULL, 4);

-- A 40-char sha, without the typo above.
UPDATE @scans SET Sha = 'b93e1d7c8a5f204e6db139c07a82f5e4610bd93c' WHERE Pr = 'refs/pull/903/merge';

-- ---- Scan job rows ---------------------------------------------------------------------------
INSERT INTO ScanJobs (Id, ProjectId, TriggeredBy, PrRef, CommitSha, Status, CorpusVersion,
                      BundlePurged, StartedAt, CompletedAt, TriggeringUserId, FailureReason,
                      ModelTierHint, RetainReport, Stage, TenantId)
SELECT
    s.NewId, @project, src.TriggeredBy, s.Pr, s.Sha, s.Status, src.CorpusVersion,
    1,                                              -- bundles are purged after the audit (SEC-29)
    DATEADD(HOUR, -s.HoursAgo, SYSUTCDATETIME()),
    CASE WHEN s.RanMins IS NULL THEN NULL
         ELSE DATEADD(MINUTE, s.RanMins, DATEADD(HOUR, -s.HoursAgo, SYSUTCDATETIME())) END,
    src.TriggeringUserId, s.Failure, src.ModelTierHint, s.Retain, s.Stage, @tenant
FROM @scans s CROSS JOIN (SELECT * FROM ScanJobs WHERE Id = @src) src;

-- ---- Pipeline output, replayed ---------------------------------------------------------------
-- Only for scans that reached the report stage. A queued or failed scan legitimately has none, and
-- giving it findings would be inventing a result the pipeline never reached.
DECLARE @id UNIQUEIDENTIFIER, @retain BIT;
DECLARE cur CURSOR LOCAL FAST_FORWARD FOR SELECT NewId, Retain FROM @scans WHERE Clone = 1;
OPEN cur;
FETCH NEXT FROM cur INTO @id, @retain;

WHILE @@FETCH_STATUS = 0
BEGIN
    -- Findings. Mapped, because a chain hop points at one.
    DECLARE @fmap TABLE (OldId UNIQUEIDENTIFIER, NewId UNIQUEIDENTIFIER);
    DELETE FROM @fmap;
    INSERT INTO @fmap SELECT Id, NEWID() FROM Findings WHERE ScanJobId = @src;

    INSERT INTO Findings (Id, ScanJobId, SourceTool, Layer, Severity, CweId, CveId, NodeRef, Message, Redacted, TenantId)
    SELECT m.NewId, @id, f.SourceTool, f.Layer, f.Severity, f.CweId, f.CveId, f.NodeRef, f.Message, f.Redacted, @tenant
    FROM Findings f JOIN @fmap m ON m.OldId = f.Id
    WHERE f.ScanJobId = @src;

    -- Graph nodes. Mapped, because an edge points at two.
    DECLARE @nmap TABLE (OldId UNIQUEIDENTIFIER, NewId UNIQUEIDENTIFIER);
    DELETE FROM @nmap;
    INSERT INTO @nmap SELECT Id, NEWID() FROM GraphNodes WHERE ScanJobId = @src;

    INSERT INTO GraphNodes (Id, ScanJobId, NodeKey, NodeType, Layer, IsHot, Attrs, TenantId)
    SELECT m.NewId, @id, n.NodeKey, n.NodeType, n.Layer, n.IsHot, n.Attrs, @tenant
    FROM GraphNodes n JOIN @nmap m ON m.OldId = n.Id
    WHERE n.ScanJobId = @src;

    -- Edges. Mapped, because a chain hop points at one.
    DECLARE @emap TABLE (OldId UNIQUEIDENTIFIER, NewId UNIQUEIDENTIFIER);
    DELETE FROM @emap;
    INSERT INTO @emap SELECT Id, NEWID() FROM GraphEdges WHERE ScanJobId = @src;

    INSERT INTO GraphEdges (Id, ScanJobId, FromNodeId, ToNodeId, Relation, Seam, Confidence, OrientedAttackDir, TenantId)
    SELECT m.NewId, @id, fn.NewId, tn.NewId, e.Relation, e.Seam, e.Confidence, e.OrientedAttackDir, @tenant
    FROM GraphEdges e
    JOIN @emap m  ON m.OldId  = e.Id
    JOIN @nmap fn ON fn.OldId = e.FromNodeId
    JOIN @nmap tn ON tn.OldId = e.ToNodeId
    WHERE e.ScanJobId = @src;

    -- Chains and their hops — the part the diagram draws.
    DECLARE @cmap TABLE (OldId UNIQUEIDENTIFIER, NewId UNIQUEIDENTIFIER);
    DELETE FROM @cmap;
    INSERT INTO @cmap SELECT Id, NEWID() FROM Chains WHERE ScanJobId = @src;

    INSERT INTO Chains (Id, ScanJobId, HopCount, Priority, Status, MinConfidence, TenantId)
    SELECT m.NewId, @id, c.HopCount, c.Priority, c.Status, c.MinConfidence, @tenant
    FROM Chains c JOIN @cmap m ON m.OldId = c.Id
    WHERE c.ScanJobId = @src;

    INSERT INTO ChainHops (Id, ChainId, FindingId, EdgeId, HopOrder, TechniqueId, TenantId, BlueVerdict)
    SELECT NEWID(), cm.NewId, fm.NewId, em.NewId, h.HopOrder, h.TechniqueId, @tenant, h.BlueVerdict
    FROM ChainHops h
    JOIN @cmap cm ON cm.OldId = h.ChainId
    LEFT JOIN @fmap fm ON fm.OldId = h.FindingId
    LEFT JOIN @emap em ON em.OldId = h.EdgeId
    WHERE h.ChainId IN (SELECT Id FROM Chains WHERE ScanJobId = @src);

    -- The report, only where retention was asked for. SEC-35: silence means delete, so a scan
    -- with Retain = 0 correctly has no report and the history row shows no Report action.
    IF @retain = 1
        INSERT INTO Reports (Id, ScanJobId, Summary, Framing, Retained, FeedbackSlot, CreatedAt, TenantId,
                             CheapTierCost, CheapTierInputTokens, CheapTierOutputTokens, CostCurrency,
                             CostRated, HighTierCost, HighTierInputTokens, HighTierOutputTokens, ModelCalls)
        SELECT NEWID(), @id, r.Summary, r.Framing, 1, r.FeedbackSlot,
               (SELECT CompletedAt FROM ScanJobs WHERE Id = @id), @tenant,
               r.CheapTierCost, r.CheapTierInputTokens, r.CheapTierOutputTokens, r.CostCurrency,
               r.CostRated, r.HighTierCost, r.HighTierInputTokens, r.HighTierOutputTokens, r.ModelCalls
        FROM Reports r WHERE r.ScanJobId = @src;

    FETCH NEXT FROM cur INTO @id, @retain;
END

CLOSE cur;
DEALLOCATE cur;

COMMIT TRANSACTION;

-- ---- What was created ------------------------------------------------------------------------
SELECT j.StartedAt, j.Status, j.Stage, LEFT(j.CommitSha, 7) AS Sha, j.PrRef,
       (SELECT COUNT(*) FROM Findings   f WHERE f.ScanJobId = j.Id) AS Findings,
       (SELECT COUNT(*) FROM Chains     c WHERE c.ScanJobId = j.Id) AS Chains,
       (SELECT COUNT(*) FROM GraphNodes n WHERE n.ScanJobId = j.Id) AS Nodes,
       (SELECT COUNT(*) FROM Reports    r WHERE r.ScanJobId = j.Id) AS Reports
FROM ScanJobs j
WHERE j.TenantId = @tenant
ORDER BY j.StartedAt DESC;
