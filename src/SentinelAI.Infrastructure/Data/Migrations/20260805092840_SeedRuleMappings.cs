using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace SentinelAI.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class SeedRuleMappings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "RuleMappings",
                columns: new[] { "Id", "CheckId", "CveId", "CweId", "Notes", "SourceTool" },
                values: new object[,]
                {
                    { new Guid("1b276ae3-0480-42a5-8449-a79a0ab218ab"), "CKV_AWS_18", null, "CWE-778", "Checkov policy catalogue: S3 access logging not enabled", "checkov" },
                    { new Guid("1daf0baa-6a14-4f71-9dda-9841409f10ee"), "AVD-AWS-0089", null, "CWE-778", "Trivy AVD misconfiguration catalogue: S3 bucket access logging disabled", "trivy" },
                    { new Guid("20d42173-70fa-4d33-acde-0fca5d4acb42"), "SCS0001", null, "CWE-78", "Security Code Scan rule catalogue: command injection", "roslyn" },
                    { new Guid("29eea3df-8e2d-4e22-8d75-a85bfa5683d3"), "SCS0029", null, "CWE-79", "Security Code Scan rule catalogue: cross-site scripting", "roslyn" },
                    { new Guid("421bbdc3-84c3-4ef7-9b24-76bb0092e491"), "CKV_AWS_19", null, "CWE-311", "Checkov policy catalogue: S3 not encrypted at rest", "checkov" },
                    { new Guid("7853dced-5fc7-4263-b765-8d0b2d72636e"), "SCS0018", null, "CWE-22", "Security Code Scan rule catalogue: path traversal", "roslyn" },
                    { new Guid("790afc1c-f4ea-46e8-989d-17176ab8f9a9"), "CKV_AWS_24", null, "CWE-284", "Checkov policy catalogue: security group allows ingress from 0.0.0.0/0 to port 22", "checkov" },
                    { new Guid("b827ed21-2d56-47bd-a7c2-b9e0153d9cfc"), "SCS0026", null, "CWE-89", "Security Code Scan rule catalogue: SQL injection", "roslyn" },
                    { new Guid("d62d3bff-5cea-408e-83b4-1a73c83b834d"), "AVD-AWS-0086", null, "CWE-284", "Trivy AVD misconfiguration catalogue: S3 public access block missing", "trivy" },
                    { new Guid("dd4f560a-16cc-462e-91d3-da21cf70de3e"), "SCS0005", null, "CWE-338", "Security Code Scan rule catalogue: weak random number generator", "roslyn" },
                    { new Guid("eef61ee4-2167-4f09-873a-8e30c5250145"), "CKV_DOCKER_3", null, "CWE-250", "Checkov policy catalogue: container has no non-root user", "checkov" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("1b276ae3-0480-42a5-8449-a79a0ab218ab"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("1daf0baa-6a14-4f71-9dda-9841409f10ee"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("20d42173-70fa-4d33-acde-0fca5d4acb42"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("29eea3df-8e2d-4e22-8d75-a85bfa5683d3"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("421bbdc3-84c3-4ef7-9b24-76bb0092e491"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("7853dced-5fc7-4263-b765-8d0b2d72636e"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("790afc1c-f4ea-46e8-989d-17176ab8f9a9"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("b827ed21-2d56-47bd-a7c2-b9e0153d9cfc"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("d62d3bff-5cea-408e-83b4-1a73c83b834d"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("dd4f560a-16cc-462e-91d3-da21cf70de3e"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("eef61ee4-2167-4f09-873a-8e30c5250145"));
        }
    }
}
