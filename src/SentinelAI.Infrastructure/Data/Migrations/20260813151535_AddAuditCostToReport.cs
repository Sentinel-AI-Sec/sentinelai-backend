using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddAuditCostToReport : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<decimal>(
                name: "CheapTierCost",
                table: "Reports",
                type: "decimal(18,6)",
                precision: 18,
                scale: 6,
                nullable: false,
                defaultValue: 0m);

            migrationBuilder.AddColumn<long>(
                name: "CheapTierInputTokens",
                table: "Reports",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<long>(
                name: "CheapTierOutputTokens",
                table: "Reports",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<string>(
                name: "CostCurrency",
                table: "Reports",
                type: "nvarchar(3)",
                maxLength: 3,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<bool>(
                name: "CostRated",
                table: "Reports",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<decimal>(
                name: "HighTierCost",
                table: "Reports",
                type: "decimal(18,6)",
                precision: 18,
                scale: 6,
                nullable: false,
                defaultValue: 0m);

            migrationBuilder.AddColumn<long>(
                name: "HighTierInputTokens",
                table: "Reports",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<long>(
                name: "HighTierOutputTokens",
                table: "Reports",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<int>(
                name: "ModelCalls",
                table: "Reports",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CheapTierCost",
                table: "Reports");

            migrationBuilder.DropColumn(
                name: "CheapTierInputTokens",
                table: "Reports");

            migrationBuilder.DropColumn(
                name: "CheapTierOutputTokens",
                table: "Reports");

            migrationBuilder.DropColumn(
                name: "CostCurrency",
                table: "Reports");

            migrationBuilder.DropColumn(
                name: "CostRated",
                table: "Reports");

            migrationBuilder.DropColumn(
                name: "HighTierCost",
                table: "Reports");

            migrationBuilder.DropColumn(
                name: "HighTierInputTokens",
                table: "Reports");

            migrationBuilder.DropColumn(
                name: "HighTierOutputTokens",
                table: "Reports");

            migrationBuilder.DropColumn(
                name: "ModelCalls",
                table: "Reports");
        }
    }
}
