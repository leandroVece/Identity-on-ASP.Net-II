using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Identity_II.Migrations
{
    /// <inheritdoc />
    public partial class tokenRefresh : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5928c7b0-960d-4bba-b8f1-7f6d38937f2e");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "a98425b5-23e3-4b6f-824c-f1321f72ee92");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "ac430c57-06b0-4337-b619-12445ec4cd73");

            migrationBuilder.RenameColumn(
                name: "TokenRefreshExpiere",
                table: "AspNetUsers",
                newName: "TokenRefreshExpiry");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "5a4d7cb4-c423-4472-9b90-d7c5b542f1d2", "1", "Admin", "ADMIN" },
                    { "664fba49-7bc0-4f55-ac57-c9e31efe3af8", "3", "HR", "RRHH" },
                    { "94e93811-d9e6-45fe-88b7-4c343a4c8e3f", "2", "User", "USER" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5a4d7cb4-c423-4472-9b90-d7c5b542f1d2");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "664fba49-7bc0-4f55-ac57-c9e31efe3af8");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "94e93811-d9e6-45fe-88b7-4c343a4c8e3f");

            migrationBuilder.RenameColumn(
                name: "TokenRefreshExpiry",
                table: "AspNetUsers",
                newName: "TokenRefreshExpiere");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "5928c7b0-960d-4bba-b8f1-7f6d38937f2e", "1", "Admin", "ADMIN" },
                    { "a98425b5-23e3-4b6f-824c-f1321f72ee92", "3", "HR", "RRHH" },
                    { "ac430c57-06b0-4337-b619-12445ec4cd73", "2", "User", "USER" }
                });
        }
    }
}
