using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SentinelAI.Infrastructure.Data.Migrations
{
    /// <summary>
    /// Audit 42-A: <c>ChainHops.BlueValidated</c> (bit) becomes <c>ChainHops.BlueVerdict</c>
    /// (the <c>HopVerdict</c> name).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Dropping the bit column loses nothing.</b> Nothing has ever written it: the only
    /// producer of hop rows is <c>CandidateChainWriter</c>, which set it to <c>false</c>
    /// literally, and no later stage updated it. Every value in this column in every database is
    /// a default, which is exactly the defect — the dashboard read those defaults as "Blue
    /// validated 0 of N steps".
    /// </para>
    /// <para>
    /// Existing rows therefore land on <c>Unassessed</c> and not on <c>Unattributed</c>: no
    /// debate ever looked at them in a way that was recorded, and back-filling anything stronger
    /// would be inventing history. The column default carries the same value for the same
    /// reason, so a row inserted by anything that does not know about this column is honest by
    /// construction rather than silently "not validated".
    /// </para>
    /// </remarks>
    public partial class AddChainHopBlueVerdict : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "BlueVerdict",
                table: "ChainHops",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "Unassessed");

            migrationBuilder.DropColumn(
                name: "BlueValidated",
                table: "ChainHops");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // The bool cannot carry the verdict back, so the down migration restores the column
            // in the only state it was ever actually in: false everywhere.
            migrationBuilder.AddColumn<bool>(
                name: "BlueValidated",
                table: "ChainHops",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.DropColumn(
                name: "BlueVerdict",
                table: "ChainHops");
        }
    }
}
