using SentinelAI.Domain.Abstractions;

namespace SentinelAI.Domain.Models
{
    public class Report : ITenantOwned
    {
        public Guid Id { get; set; }
        public Guid TenantId { get; set; }
        public Guid ScanJobId { get; set; }
        public string Summary { get; set; } = string.Empty;
        public string Framing { get; set; } = string.Empty;
        public bool Retained { get; set; }
        public string? FeedbackSlot { get; set; }
        public DateTime CreatedAt { get; set; }

        // ---- SEC-31: what this audit cost, split by model tier ---------------------------
        // Flattened onto the report rather than kept in a child table: there are exactly two
        // tiers, they are fixed by ModelTier, and a scan has exactly one report — so a table
        // would buy nothing and cost a join on every read. Tokens and money are both stored
        // because only the tokens are certain; the money is the tokens times a rate we
        // configured, and CostRated records whether such a rate existed at all.

        /// <summary>ISO code the cost figures are quoted in.</summary>
        public string CostCurrency { get; set; } = "USD";

        /// <summary>Prompt tokens billed by the high (reasoning) tier.</summary>
        public long HighTierInputTokens { get; set; }

        /// <summary>Completion tokens billed by the high (reasoning) tier.</summary>
        public long HighTierOutputTokens { get; set; }

        /// <summary>Money spent on the high tier. Zero when the tier had no configured rate.</summary>
        public decimal HighTierCost { get; set; }

        /// <summary>Prompt tokens billed by the cheap (routine) tier.</summary>
        public long CheapTierInputTokens { get; set; }

        /// <summary>Completion tokens billed by the cheap (routine) tier.</summary>
        public long CheapTierOutputTokens { get; set; }

        /// <summary>Money spent on the cheap tier. Zero when the tier had no configured rate.</summary>
        public decimal CheapTierCost { get; set; }

        /// <summary>Model calls the audit made, across both tiers.</summary>
        public int ModelCalls { get; set; }

        /// <summary>
        /// False when tokens were spent on a tier that had no price configured, so the stored
        /// cost is an under-count rather than the bill. Without it a missing rate is
        /// indistinguishable from a free scan once the numbers are in the database.
        /// </summary>
        public bool CostRated { get; set; }

        /// <summary>Total money across both tiers.</summary>
        public decimal TotalCost => HighTierCost + CheapTierCost;

        public ScanJob? ScanJob { get; set; }
        public ICollection<Citation> Citations { get; set; } = new List<Citation>();
    }
}
