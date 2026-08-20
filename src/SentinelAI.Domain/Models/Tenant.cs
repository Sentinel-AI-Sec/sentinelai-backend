namespace SentinelAI.Domain.Models
{
    public class Tenant
    {
        public Guid Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string PlanTier { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }

        public ICollection<User> Users { get; set; } = new List<User>();
        public ICollection<Project> Projects { get; set; } = new List<Project>();

        /// <summary>
        /// What this organization is paying for, or null if it has never started a checkout.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Null and <see cref="Enums.SubscriptionStatus.None"/> mean the same thing to a reader —
        /// the free tier — and both occur: a tenant that never opened the billing screen has no
        /// row, and one that abandoned a payment page has a row holding only a Stripe customer
        /// id. <c>GET /v1/billing/subscription</c> collapses the two so no caller has to know
        /// which it is looking at.
        /// </para>
        /// <para>
        /// <see cref="PlanTier"/> above stays the field the rest of the product reads for
        /// entitlement. The webhook handler keeps it in step with this, so a feature gate never
        /// has to understand Stripe's status vocabulary to decide what an account may do.
        /// </para>
        /// </remarks>
        public Subscription? Subscription { get; set; }
    }
}
