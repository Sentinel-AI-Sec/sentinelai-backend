
using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Data
{
    public class SentinelDbContext : DbContext
    {
        public SentinelDbContext(DbContextOptions<SentinelDbContext> options)
            : base(options)
        {
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

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.ApplyConfigurationsFromAssembly(typeof(SentinelDbContext).Assembly);
        }
    }
}