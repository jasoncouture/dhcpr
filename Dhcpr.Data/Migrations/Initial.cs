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
                name: "CacheEntries",
                columns: table => new
                {
                    Id = table.Column<string>(type: "TEXT", nullable: false),
                    Name = table.Column<string>(type: "TEXT", maxLength: 255, nullable: false),
                    Type = table.Column<int>(type: "INTEGER", nullable: false),
                    Class = table.Column<int>(type: "INTEGER", nullable: false),
                    Payload = table.Column<byte[]>(type: "BLOB", maxLength: 2048, nullable: false),
                    TimeToLive = table.Column<double>(type: "REAL", nullable: false),
                    Created = table.Column<long>(type: "INTEGER", nullable: false),
                    Modified = table.Column<long>(type: "INTEGER", nullable: false),
                    Expires = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CacheEntries", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "NameRecords",
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
                    table.PrimaryKey("PK_NameRecords", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ResourceRecords",
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
                    table.PrimaryKey("PK_ResourceRecords", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ResourceRecords_NameRecords_ParentId",
                        column: x => x.ParentId,
                        principalTable: "NameRecords",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CacheEntries_Name_Type_Class",
                table: "CacheEntries",
                columns: new[] { "Name", "Type", "Class" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_NameRecords_Name",
                table: "NameRecords",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ResourceRecords_ParentId",
                table: "ResourceRecords",
                column: "ParentId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CacheEntries");

            migrationBuilder.DropTable(
                name: "ResourceRecords");

            migrationBuilder.DropTable(
                name: "NameRecords");
        }
    }
}
