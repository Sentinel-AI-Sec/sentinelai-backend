using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddTenantIsolation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "ScanJobs",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "ScanBundles",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "Reports",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "GraphNodes",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "GraphEdges",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "Findings",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "Citations",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "Chains",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "TenantId",
                table: "ChainHops",
                type: "uniqueidentifier",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.CreateIndex(
                name: "IX_ScanJobs_TenantId",
                table: "ScanJobs",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_ScanBundles_TenantId",
                table: "ScanBundles",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Reports_TenantId",
                table: "Reports",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_GraphNodes_TenantId",
                table: "GraphNodes",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_GraphEdges_TenantId",
                table: "GraphEdges",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Findings_TenantId",
                table: "Findings",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Citations_TenantId",
                table: "Citations",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_Chains_TenantId",
                table: "Chains",
                column: "TenantId");

            migrationBuilder.CreateIndex(
                name: "IX_ChainHops_TenantId",
                table: "ChainHops",
                column: "TenantId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ScanJobs_TenantId",
                table: "ScanJobs");

            migrationBuilder.DropIndex(
                name: "IX_ScanBundles_TenantId",
                table: "ScanBundles");

            migrationBuilder.DropIndex(
                name: "IX_Reports_TenantId",
                table: "Reports");

            migrationBuilder.DropIndex(
                name: "IX_GraphNodes_TenantId",
                table: "GraphNodes");

            migrationBuilder.DropIndex(
                name: "IX_GraphEdges_TenantId",
                table: "GraphEdges");

            migrationBuilder.DropIndex(
                name: "IX_Findings_TenantId",
                table: "Findings");

            migrationBuilder.DropIndex(
                name: "IX_Citations_TenantId",
                table: "Citations");

            migrationBuilder.DropIndex(
                name: "IX_Chains_TenantId",
                table: "Chains");

            migrationBuilder.DropIndex(
                name: "IX_ChainHops_TenantId",
                table: "ChainHops");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "ScanJobs");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "ScanBundles");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "Reports");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "GraphNodes");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "GraphEdges");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "Citations");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "Chains");

            migrationBuilder.DropColumn(
                name: "TenantId",
                table: "ChainHops");
        }
    }
}
