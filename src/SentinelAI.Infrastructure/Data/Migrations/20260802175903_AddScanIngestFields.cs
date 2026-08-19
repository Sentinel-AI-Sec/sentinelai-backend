using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddScanIngestFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "FailureReason",
                table: "ScanJobs",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ModelTierHint",
                table: "ScanJobs",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<bool>(
                name: "RetainReport",
                table: "ScanJobs",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "Stage",
                table: "ScanJobs",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Sha256",
                table: "ScanBundles",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<long>(
                name: "SizeBytes",
                table: "ScanBundles",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<string>(
                name: "StorageLocator",
                table: "ScanBundles",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "FailureReason",
                table: "ScanJobs");

            migrationBuilder.DropColumn(
                name: "ModelTierHint",
                table: "ScanJobs");

            migrationBuilder.DropColumn(
                name: "RetainReport",
                table: "ScanJobs");

            migrationBuilder.DropColumn(
                name: "Stage",
                table: "ScanJobs");

            migrationBuilder.DropColumn(
                name: "Sha256",
                table: "ScanBundles");

            migrationBuilder.DropColumn(
                name: "SizeBytes",
                table: "ScanBundles");

            migrationBuilder.DropColumn(
                name: "StorageLocator",
                table: "ScanBundles");
        }
    }
}
