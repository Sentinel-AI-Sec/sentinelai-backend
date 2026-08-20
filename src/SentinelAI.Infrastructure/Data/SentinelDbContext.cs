
using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data
{
    public class SentinelDbContext : DbContext
    {
        /// <summary>
        /// The caller's tenant, captured once at construction. <c>Guid.Empty</c> when there
        /// is no authenticated caller (no HTTP request — e.g. EF design-time tooling) rather
        /// than null, so the query filter below is a plain equality check: every
        /// <see cref="ITenantOwned"/> row belongs to a real tenant, never to
        /// <c>Guid.Empty</c>, so an unauthenticated context sees nothing instead of
        /// everything (SEC-32: fail closed, not open).
        /// </summary>
        public Guid CurrentTenantId { get; }

        public SentinelDbContext(DbContextOptions<SentinelDbContext> options, ICallerContext callerContext)
            : base(options)
        {
            CurrentTenantId = callerContext.TenantId ?? Guid.Empty;
        }

        public DbSet<Tenant> Tenants { get; set; }
        public DbSet<User> Users { get; set; }
        public DbSet<Project> Projects { get; set; }
        public DbSet<ScanJob> ScanJobs { get; set; }
        public DbSet<ScanBundle> ScanBundles { get; set; }
        public DbSet<Finding> Findings { get; set; }
        public DbSet<GraphNode> GraphNodes { get; set; }
        public DbSet<GraphEdge> GraphEdges { get; set; }
        public DbSet<Chain> Chains { get; set; }
        public DbSet<ChainHop> ChainHops { get; set; }
        public DbSet<Report> Reports { get; set; }
        public DbSet<Citation> Citations { get; set; }
        public DbSet<RuleMapping> RuleMappings { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<Subscription> Subscriptions { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(SentinelDbContext).Assembly);

            ApplyTenantIsolation(modelBuilder);
        }

        /// <summary>
        /// Applies a tenant query filter — and a supporting index — to every entity that
        /// implements <see cref="ITenantOwned"/>, by reflection, rather than one
        /// <c>HasQueryFilter</c> call per entity type configuration.
        /// </summary>
        /// <remarks>
        /// SEC-32's own warning is "filtering by tenant in some queries but not all — one
        /// forgotten query is a data leak." A per-entity filter call is still one forgotten
        /// <em>entity</em> away from the same failure the day a new table is added. This
        /// reads the model instead: any entity that implements the interface is isolated
        /// automatically, with nothing to remember at the call site or in a config class.
        /// </remarks>
        // Instance method, deliberately not static: the filter closes over `this` so it
        // reads CurrentTenantId off the live context at query time, not at model-build time.
        private void ApplyTenantIsolation(ModelBuilder modelBuilder)
        {
            var contextInstance = Expression.Constant(this);

            foreach (var entityType in modelBuilder.Model.GetEntityTypes())
            {
                if (!typeof(ITenantOwned).IsAssignableFrom(entityType.ClrType))
                    continue;

                var entity = modelBuilder.Entity(entityType.ClrType);
                entity.HasIndex(nameof(ITenantOwned.TenantId));

                // e => e.TenantId == this.CurrentTenantId
                var parameter = Expression.Parameter(entityType.ClrType, "e");
                var tenantIdProperty = Expression.Property(parameter, nameof(ITenantOwned.TenantId));
                var currentTenantId = Expression.Property(contextInstance, nameof(CurrentTenantId));
                var filter = Expression.Lambda(Expression.Equal(tenantIdProperty, currentTenantId), parameter);

                entity.HasQueryFilter(filter);
            }
        }
    }
}
