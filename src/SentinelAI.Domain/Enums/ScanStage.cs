namespace SentinelAI.Domain.Enums;

public enum ScanStage
{
    /// <summary>Bundle accepted and stored; nothing consumed yet.</summary>
    Received,
 
    /// <summary>SARIF/JSON parsed into the unified Finding set, CWEs resolved.</summary>
    Normalize,
 
    /// <summary>Resource graph built from the shipped inputs; candidate chains generated.</summary>
    Graph,
 
    /// <summary>Findings queried against the offense/defense collections.</summary>
    Retrieve,
 
    /// <summary>Red asserts, Blue validates, Reporter adjudicates.</summary>
    Debate,
 
    /// <summary>Draft audit emitted with citations.</summary>
    Report
}