using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddScanAuditIntegrity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ScanAuditIntegrities",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ScanJobId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    Adjudicated = table.Column<bool>(type: "bit", nullable: false),
                    Outcome = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Rounds = table.Column<int>(type: "int", nullable: false),
                    VerdictReadable = table.Column<bool>(type: "bit", nullable: false),
                    TerminatedByTurnCap = table.Column<bool>(type: "bit", nullable: false),
                    WeakestJoin = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    EdgeIntegrityWarnings = table.Column<int>(type: "int", nullable: false),
                    EdgeIntegrityDetail = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    AbandonedReasoningWarnings = table.Column<int>(type: "int", nullable: false),
                    AbandonedReasoningDetail = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    RetrievalFindings = table.Column<int>(type: "int", nullable: false),
                    RetrievalGrounded = table.Column<int>(type: "int", nullable: false),
                    CoveragePercent = table.Column<int>(type: "int", nullable: false),
                    ModesThatDidNotFire = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    CandidateChains = table.Column<int>(type: "int", nullable: false),
                    ChainsAdjudicated = table.Column<int>(type: "int", nullable: false),
                    CorpusVersion = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    HarnessVersion = table.Column<int>(type: "int", nullable: false),
                    CreatedAt = table.Column<DateTime>(type: "datetime2", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanAuditIntegrities", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ScanAuditIntegrities_ScanJobs_ScanJobId",
                        column: x => x.ScanJobId,
                        principalTable: "ScanJobs",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ScanAuditIntegrities_ScanJobId",
                table: "ScanAuditIntegrities",
                column: "ScanJobId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ScanAuditIntegrities_TenantId",
                table: "ScanAuditIntegrities",
                column: "TenantId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ScanAuditIntegrities");
        }
    }
}
