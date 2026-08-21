using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddChronologicalListIndexes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateIndex(
                name: "IX_ScanJobs_TenantId_StartedAt_Id",
                table: "ScanJobs",
                columns: new[] { "TenantId", "StartedAt", "Id" });

            migrationBuilder.CreateIndex(
                name: "IX_Reports_TenantId_CreatedAt_Id",
                table: "Reports",
                columns: new[] { "TenantId", "CreatedAt", "Id" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ScanJobs_TenantId_StartedAt_Id",
                table: "ScanJobs");

            migrationBuilder.DropIndex(
                name: "IX_Reports_TenantId_CreatedAt_Id",
                table: "Reports");
        }
    }
}
