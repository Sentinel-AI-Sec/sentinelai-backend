
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

            modelBuilder.Entity<GraphNode>()
                .HasIndex(g => new { g.ScanJobId, g.NodeKey })
                .IsUnique();

            modelBuilder.Entity<RuleMapping>()
                .HasIndex(r => new { r.SourceTool, r.CheckId })
                .IsUnique();

            modelBuilder.Entity<ScanJob>()
                .HasOne(s => s.ScanBundle)
                .WithOne(b => b.ScanJob)
                .HasForeignKey<ScanBundle>(b => b.ScanJobId);

            modelBuilder.Entity<ScanJob>()
                .HasOne(s => s.Report)
                .WithOne(r => r.ScanJob)
                .HasForeignKey<Report>(r => r.ScanJobId);

            modelBuilder.Entity<GraphEdge>()
                .HasOne(e => e.FromNode)
                .WithMany(n => n.OutgoingEdges)
                .HasForeignKey(e => e.FromNodeId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<GraphEdge>()
                .HasOne(e => e.ToNode)
                .WithMany(n => n.IncomingEdges)
                .HasForeignKey(e => e.ToNodeId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<ChainHop>()
                .HasOne(ch => ch.Finding)
                .WithMany(f => f.ChainHops)
                .HasForeignKey(ch => ch.FindingId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<ChainHop>()
                .HasOne(ch => ch.Chain)
                .WithMany(c => c.ChainHops)
                .HasForeignKey(ch => ch.ChainId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<ChainHop>()
                .HasOne(ch => ch.Edge)
                .WithMany(e => e.ChainHops)
                .HasForeignKey(ch => ch.EdgeId)
                .OnDelete(DeleteBehavior.Restrict);

            modelBuilder.Entity<RuleMapping>().HasData(
                new RuleMapping
                {
                    Id = Guid.Parse("f099c288-0f0c-43f1-b956-f6a6233ba3eb"),
                    SourceTool = "roslyn",
                    CheckId = "SCS0028",
                    CweId = "CWE-502",
                    Notes = "Baseline exact lookup map"
                },
                new RuleMapping
                {
                    Id = Guid.Parse("b882650b-47e1-4c07-ba96-7fc3b8a13a21"),
                    SourceTool = "checkov",
                    CheckId = "CKV_AWS_20",
                    CweId = "CWE-284",
                    Notes = "Baseline exact lookup map"
                }
            );
        }
    }
}