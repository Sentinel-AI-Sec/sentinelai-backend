using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddScanQuotaCounters : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ScanQuotaCounters",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    TenantId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    UtcDay = table.Column<DateOnly>(type: "date", nullable: false),
                    Count = table.Column<int>(type: "int", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScanQuotaCounters", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ScanQuotaCounters_Tenants_TenantId",
                        column: x => x.TenantId,
                        principalTable: "Tenants",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ScanQuotaCounters_TenantId",
                table: "ScanQuotaCounters",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_ScanQuotaCounters_TenantId_UtcDay",
                table: "ScanQuotaCounters",
                columns: new[] { "TenantId", "UtcDay" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ScanQuotaCounters");
        }
    }
}
