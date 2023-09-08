using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Dhcpr.Data.Migrations
{
    /// <inheritdoc />
    public partial class DbCache : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "CacheEntry",
                table: "DnsNameRecord",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CacheEntry",
                table: "DnsNameRecord");
        }
    }
}
