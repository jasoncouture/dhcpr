using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Dhcpr.Data.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DnsNameRecord",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    NxDomainIfNoRecords = table.Column<bool>(type: "INTEGER", nullable: false),
                    Created = table.Column<long>(type: "INTEGER", nullable: false),
                    Modified = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DnsNameRecord", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DnsResourceRecord",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    OwnerId = table.Column<string>(type: "TEXT", nullable: false),
                    ParentId = table.Column<string>(type: "TEXT", nullable: false),
                    RecordType = table.Column<int>(type: "INTEGER", nullable: false),
                    Class = table.Column<int>(type: "INTEGER", nullable: false),
                    Section = table.Column<int>(type: "INTEGER", nullable: false),
                    TimeToLive = table.Column<double>(type: "REAL", nullable: false),
                    Created = table.Column<long>(type: "INTEGER", nullable: false),
                    Modified = table.Column<long>(type: "INTEGER", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    InterNetworkVersion4Address = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 4, nullable: true),
                    InterNetworkVersion6Address = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 16, nullable: true),
                    Preference = table.Column<ushort>(type: "INTEGER", nullable: true),
                    Priority = table.Column<ushort>(type: "INTEGER", nullable: true),
                    Weight = table.Column<ushort>(type: "INTEGER", nullable: true),
                    Port = table.Column<ushort>(type: "INTEGER", nullable: true),
                    Master = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    Responsible = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true),
                    Serial = table.Column<long>(type: "INTEGER", nullable: true),
                    Refresh = table.Column<double>(type: "REAL", nullable: true),
                    Retry = table.Column<double>(type: "REAL", nullable: true),
                    Expire = table.Column<double>(type: "REAL", nullable: true),
                    MinTtl = table.Column<double>(type: "REAL", nullable: true),
                    Ttl = table.Column<double>(type: "REAL", nullable: true),
                    Text = table.Column<string>(type: "TEXT", maxLength: 255, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DnsResourceRecord", x => x.Id);
                    table.ForeignKey(
                        name: "FK_DnsResourceRecord_DnsNameRecord_ParentId",
                        column: x => x.ParentId,
                        principalTable: "DnsNameRecord",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DnsNameRecord_Name",
                table: "DnsNameRecord",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DnsResourceRecord_ParentId",
                table: "DnsResourceRecord",
                column: "ParentId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DnsResourceRecord");

            migrationBuilder.DropTable(
                name: "DnsNameRecord");
        }
    }
}
