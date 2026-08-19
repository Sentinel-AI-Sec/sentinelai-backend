using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace SentinelAI.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class ReseedRuleMappingsFromScannerOutput : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("421bbdc3-84c3-4ef7-9b24-76bb0092e491"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("790afc1c-f4ea-46e8-989d-17176ab8f9a9"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("b882650b-47e1-4c07-ba96-7fc3b8a13a21"));

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("1b276ae3-0480-42a5-8449-a79a0ab218ab"),
                column: "Notes",
                value: "Checkov policy: S3 access logging not enabled");

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("1daf0baa-6a14-4f71-9dda-9841409f10ee"),
                columns: new[] { "CheckId", "Notes" },
                values: new object[] { "AWS-0089", "Trivy AVD misconfiguration: S3 bucket access logging disabled" });

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("20d42173-70fa-4d33-acde-0fca5d4acb42"),
                column: "Notes",
                value: "Security Code Scan: OS command injection");

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("29eea3df-8e2d-4e22-8d75-a85bfa5683d3"),
                column: "Notes",
                value: "Security Code Scan: cross-site scripting");

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("7853dced-5fc7-4263-b765-8d0b2d72636e"),
                column: "Notes",
                value: "Security Code Scan: path traversal");

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("b827ed21-2d56-47bd-a7c2-b9e0153d9cfc"),
                columns: new[] { "CweId", "Notes" },
                values: new object[] { "CWE-90", "Security Code Scan: LDAP injection" });

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("d62d3bff-5cea-408e-83b4-1a73c83b834d"),
                columns: new[] { "CheckId", "Notes" },
                values: new object[] { "AWS-0086", "Trivy AVD misconfiguration: S3 public access block missing" });

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("dd4f560a-16cc-462e-91d3-da21cf70de3e"),
                column: "Notes",
                value: "Security Code Scan: weak random number generator");

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("eef61ee4-2167-4f09-873a-8e30c5250145"),
                column: "Notes",
                value: "Checkov policy: container has no non-root user");

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("f099c288-0f0c-43f1-b956-f6a6233ba3eb"),
                column: "Notes",
                value: "Security Code Scan: unsafe deserialization");

            migrationBuilder.InsertData(
                table: "RuleMappings",
                columns: new[] { "Id", "CheckId", "CveId", "CweId", "Notes", "SourceTool" },
                values: new object[,]
                {
                    { new Guid("05b3ae46-c1c2-44f3-b687-acbcdef01234"), "CKV_DOCKER_2", null, "CWE-693", "Checkov policy: image has no HEALTHCHECK", "checkov" },
                    { new Guid("05b3ae46-c1d2-44f3-b687-ac1d2e3f4011"), "CKV_AWS_290", null, "CWE-732", "Checkov policy: IAM policy allows unconstrained write", "checkov" },
                    { new Guid("12f18d7c-e69e-4cde-9a0f-b12ddd332647"), "CKV_AWS_288", null, "CWE-732", "Checkov policy: IAM policy allows data exfiltration", "checkov" },
                    { new Guid("16c4bf57-d2d3-4504-c798-bdcdef012345"), "CKV_SECRET_6", null, "CWE-798", "Checkov policy: hardcoded secret in the image", "checkov" },
                    { new Guid("16c4bf57-d2e3-4504-c798-bd2e3f405122"), "CKV_AWS_355", null, "CWE-732", "Checkov policy: IAM policy uses \"*\" as a resource", "checkov" },
                    { new Guid("27d5c068-e3e4-4615-d8a9-cedef0123456"), "AWS-0087", null, "CWE-284", "Trivy AVD misconfiguration: S3 block public ACLs disabled", "trivy" },
                    { new Guid("27d5c068-e3f4-4615-d8a9-ce3f40516233"), "CKV_AWS_53", null, "CWE-284", "Checkov policy: S3 block public ACLs disabled", "checkov" },
                    { new Guid("38e6d179-f405-4726-e9ba-df4051627344"), "CKV_AWS_54", null, "CWE-284", "Checkov policy: S3 block public policy disabled", "checkov" },
                    { new Guid("38e6d179-f4f5-4726-e9ba-dfef01234567"), "AWS-0090", null, "CWE-693", "Trivy AVD misconfiguration: S3 versioning disabled", "trivy" },
                    { new Guid("49f7e28a-0506-4837-facb-e0f012345678"), "AWS-0091", null, "CWE-284", "Trivy AVD misconfiguration: S3 block public policy disabled", "trivy" },
                    { new Guid("49f7e28a-0516-4837-facb-e05162738455"), "CKV_AWS_55", null, "CWE-284", "Checkov policy: S3 ignore public ACLs disabled", "checkov" },
                    { new Guid("5a08f39b-1617-4948-0bdc-f10123456789"), "AWS-0093", null, "CWE-284", "Trivy AVD misconfiguration: S3 restrict public buckets disabled", "trivy" },
                    { new Guid("5a08f39b-1627-4948-0bdc-f16273849566"), "CKV_AWS_56", null, "CWE-284", "Checkov policy: S3 restrict_public_buckets disabled", "checkov" },
                    { new Guid("6b1904ac-2728-4a59-1ced-02123456789a"), "AWS-0094", null, "CWE-284", "Trivy AVD misconfiguration: S3 bucket has a public ACL", "trivy" },
                    { new Guid("6b1904ac-2738-4a59-1ced-027384950677"), "CKV2_AWS_6", null, "CWE-284", "Checkov policy: S3 bucket has no public access block", "checkov" },
                    { new Guid("6b1f0a4c-1d2e-4a3b-9c5d-2e7f8a9b0c11"), "SCS0002", null, "CWE-89", "Security Code Scan: SQL injection", "roslyn" },
                    { new Guid("7c2a15bd-3839-4b6a-2dfe-1323456789ab"), "AWS-0104", null, "CWE-284", "Trivy AVD misconfiguration: security group allows unrestricted egress", "trivy" },
                    { new Guid("7c2a15bd-3849-4b6a-2dfe-138495061788"), "CKV_AWS_145", null, "CWE-311", "Checkov policy: S3 not encrypted with KMS", "checkov" },
                    { new Guid("7c2a1b5d-3e4f-4b6a-8d9e-1f2a3b4c5d22"), "SCS0006", null, "CWE-328", "Security Code Scan: weak hashing function", "roslyn" },
                    { new Guid("8d3b26ce-493a-4c7b-3e0f-2423456789bc"), "AWS-0124", null, "CWE-1059", "Trivy AVD misconfiguration: security group rule has no description", "trivy" },
                    { new Guid("8d3b26ce-494a-4c7b-3e0f-249506172899"), "CKV_AWS_21", null, "CWE-693", "Checkov policy: S3 versioning disabled", "checkov" },
                    { new Guid("8d3b2c6e-4f5a-4c7b-9e0f-2a3b4c5d6e33"), "SCS0007", null, "CWE-611", "Security Code Scan: XML external entity (XXE)", "roslyn" },
                    { new Guid("9299d45f-8be7-407f-8569-6cfc77d22943"), "CKV2_AWS_62", null, "CWE-778", "Checkov policy: S3 event notifications disabled", "checkov" },
                    { new Guid("9e4c37df-5a4b-4d8c-4f10-353456789bcd"), "AWS-0132", null, "CWE-311", "Trivy AVD misconfiguration: S3 not encrypted with a customer-managed key", "trivy" },
                    { new Guid("9e4c37df-5a5b-4d8c-4f10-35061728399a"), "CKV_AWS_144", null, "CWE-693", "Checkov policy: S3 cross-region replication disabled", "checkov" },
                    { new Guid("9e4c3d7f-5a6b-4d8c-af10-3b4c5d6e7f44"), "SCS0004", null, "CWE-295", "Security Code Scan: certificate validation disabled", "roslyn" },
                    { new Guid("af5d48e0-6b5c-4e9d-5021-46456789bcde"), "AWS-0345", null, "CWE-1327", "Trivy AVD misconfiguration: ECS service assigned a public IP", "trivy" },
                    { new Guid("af5d48e0-6b6c-4e9d-5021-4617283949ab"), "CKV2_AWS_61", null, "CWE-693", "Checkov policy: S3 has no lifecycle configuration", "checkov" },
                    { new Guid("af5d4e80-6b7c-4e9d-b021-4c5d6e7f8a55"), "SCS0010", null, "CWE-327", "Security Code Scan: weak cipher algorithm", "roslyn" },
                    { new Guid("b06e59f1-7c6d-4fae-6132-5756789bcdef"), "DS-0002", null, "CWE-250", "Trivy AVD misconfiguration: container runs as root", "trivy" },
                    { new Guid("b06e5f91-7c8d-4fae-c132-5d6e7f8a9b66"), "SCS0012", null, "CWE-862", "Security Code Scan: authorization bypass", "roslyn" },
                    { new Guid("b7c1f622-1689-4892-bb30-00e6aa54bb8b"), "DS-0031", null, "CWE-798", "Trivy AVD misconfiguration: secret exposed in an image layer", "trivy" },
                    { new Guid("c17f6a02-8d7e-40bf-7243-68789bcdef01"), "DS-0026", null, "CWE-693", "Trivy AVD misconfiguration: image has no HEALTHCHECK", "trivy" },
                    { new Guid("c17f6a02-8d9e-40bf-d243-6e7f8a9b0c77"), "SCS0015", null, "CWE-798", "Security Code Scan: hardcoded credential", "roslyn" },
                    { new Guid("d2807b13-9eaf-41c0-e354-7f8a9b0c1d88"), "SCS0016", null, "CWE-352", "Security Code Scan: cross-site request forgery", "roslyn" },
                    { new Guid("dcf54bae-4eba-42f2-891a-06d3a3ed9b60"), "CKV_AWS_23", null, "CWE-1059", "Checkov policy: security group rule has no description", "checkov" },
                    { new Guid("e3918c24-afa0-42d1-9465-8a5abcdef012"), "CKV_AWS_333", null, "CWE-1327", "Checkov policy: ECS service assigned a public IP", "checkov" },
                    { new Guid("ea1979fc-cd3b-48c7-8dbe-16923dfc13db"), "CKV_AWS_249", null, "CWE-250", "Checkov policy: ECS execution and task roles are the same", "checkov" },
                    { new Guid("f4a29d35-b0b1-43e2-a576-9babcdef0123"), "CKV_AWS_336", null, "CWE-732", "Checkov policy: ECS container root filesystem is writable", "checkov" },
                    { new Guid("f4a29d35-b0c1-43e2-a576-9b0c1d2e3f00"), "CKV_AWS_289", null, "CWE-732", "Checkov policy: IAM policy allows permissions management", "checkov" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("05b3ae46-c1c2-44f3-b687-acbcdef01234"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("05b3ae46-c1d2-44f3-b687-ac1d2e3f4011"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("12f18d7c-e69e-4cde-9a0f-b12ddd332647"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("16c4bf57-d2d3-4504-c798-bdcdef012345"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("16c4bf57-d2e3-4504-c798-bd2e3f405122"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("27d5c068-e3e4-4615-d8a9-cedef0123456"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("27d5c068-e3f4-4615-d8a9-ce3f40516233"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("38e6d179-f405-4726-e9ba-df4051627344"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("38e6d179-f4f5-4726-e9ba-dfef01234567"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("49f7e28a-0506-4837-facb-e0f012345678"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("49f7e28a-0516-4837-facb-e05162738455"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("5a08f39b-1617-4948-0bdc-f10123456789"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("5a08f39b-1627-4948-0bdc-f16273849566"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("6b1904ac-2728-4a59-1ced-02123456789a"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("6b1904ac-2738-4a59-1ced-027384950677"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("6b1f0a4c-1d2e-4a3b-9c5d-2e7f8a9b0c11"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("7c2a15bd-3839-4b6a-2dfe-1323456789ab"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("7c2a15bd-3849-4b6a-2dfe-138495061788"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("7c2a1b5d-3e4f-4b6a-8d9e-1f2a3b4c5d22"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("8d3b26ce-493a-4c7b-3e0f-2423456789bc"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("8d3b26ce-494a-4c7b-3e0f-249506172899"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("8d3b2c6e-4f5a-4c7b-9e0f-2a3b4c5d6e33"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("9299d45f-8be7-407f-8569-6cfc77d22943"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("9e4c37df-5a4b-4d8c-4f10-353456789bcd"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("9e4c37df-5a5b-4d8c-4f10-35061728399a"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("9e4c3d7f-5a6b-4d8c-af10-3b4c5d6e7f44"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("af5d48e0-6b5c-4e9d-5021-46456789bcde"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("af5d48e0-6b6c-4e9d-5021-4617283949ab"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("af5d4e80-6b7c-4e9d-b021-4c5d6e7f8a55"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("b06e59f1-7c6d-4fae-6132-5756789bcdef"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("b06e5f91-7c8d-4fae-c132-5d6e7f8a9b66"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("b7c1f622-1689-4892-bb30-00e6aa54bb8b"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("c17f6a02-8d7e-40bf-7243-68789bcdef01"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("c17f6a02-8d9e-40bf-d243-6e7f8a9b0c77"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("d2807b13-9eaf-41c0-e354-7f8a9b0c1d88"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("dcf54bae-4eba-42f2-891a-06d3a3ed9b60"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("e3918c24-afa0-42d1-9465-8a5abcdef012"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("ea1979fc-cd3b-48c7-8dbe-16923dfc13db"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("f4a29d35-b0b1-43e2-a576-9babcdef0123"));

            migrationBuilder.DeleteData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("f4a29d35-b0c1-43e2-a576-9b0c1d2e3f00"));

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("1b276ae3-0480-42a5-8449-a79a0ab218ab"),
                column: "Notes",
                value: "Checkov policy catalogue: S3 access logging not enabled");

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("1daf0baa-6a14-4f71-9dda-9841409f10ee"),
                columns: new[] { "CheckId", "Notes" },
                values: new object[] { "AVD-AWS-0089", "Trivy AVD misconfiguration catalogue: S3 bucket access logging disabled" });

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("20d42173-70fa-4d33-acde-0fca5d4acb42"),
                column: "Notes",
                value: "Security Code Scan rule catalogue: command injection");

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("29eea3df-8e2d-4e22-8d75-a85bfa5683d3"),
                column: "Notes",
                value: "Security Code Scan rule catalogue: cross-site scripting");

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("7853dced-5fc7-4263-b765-8d0b2d72636e"),
                column: "Notes",
                value: "Security Code Scan rule catalogue: path traversal");

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("b827ed21-2d56-47bd-a7c2-b9e0153d9cfc"),
                columns: new[] { "CweId", "Notes" },
                values: new object[] { "CWE-89", "Security Code Scan rule catalogue: SQL injection" });

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("d62d3bff-5cea-408e-83b4-1a73c83b834d"),
                columns: new[] { "CheckId", "Notes" },
                values: new object[] { "AVD-AWS-0086", "Trivy AVD misconfiguration catalogue: S3 public access block missing" });

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("dd4f560a-16cc-462e-91d3-da21cf70de3e"),
                column: "Notes",
                value: "Security Code Scan rule catalogue: weak random number generator");

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("eef61ee4-2167-4f09-873a-8e30c5250145"),
                column: "Notes",
                value: "Checkov policy catalogue: container has no non-root user");

            migrationBuilder.UpdateData(
                table: "RuleMappings",
                keyColumn: "Id",
                keyValue: new Guid("f099c288-0f0c-43f1-b956-f6a6233ba3eb"),
                column: "Notes",
                value: "Baseline exact lookup map");

            migrationBuilder.InsertData(
                table: "RuleMappings",
                columns: new[] { "Id", "CheckId", "CveId", "CweId", "Notes", "SourceTool" },
                values: new object[,]
                {
                    { new Guid("421bbdc3-84c3-4ef7-9b24-76bb0092e491"), "CKV_AWS_19", null, "CWE-311", "Checkov policy catalogue: S3 not encrypted at rest", "checkov" },
                    { new Guid("790afc1c-f4ea-46e8-989d-17176ab8f9a9"), "CKV_AWS_24", null, "CWE-284", "Checkov policy catalogue: security group allows ingress from 0.0.0.0/0 to port 22", "checkov" },
                    { new Guid("b882650b-47e1-4c07-ba96-7fc3b8a13a21"), "CKV_AWS_20", null, "CWE-284", "Baseline exact lookup map", "checkov" }
                });
        }
    }
}
