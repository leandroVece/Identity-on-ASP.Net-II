using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace Identity_II.Migrations
{
    /// <inheritdoc />
    public partial class AplicationUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "14400c1a-e155-4826-8ba5-1d4ea6c17ddc");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "40be5e6d-264f-49b1-a48e-cb0cb1add4f2");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "f1cd1bc8-3894-4c9e-a143-bd16bd33956b");

            migrationBuilder.AddColumn<string>(
                name: "TokenRefresh",
                table: "AspNetUsers",
                type: "TEXT",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<DateTime>(
                name: "TokenRefreshExpiere",
                table: "AspNetUsers",
                type: "TEXT",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

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

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
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

            migrationBuilder.DropColumn(
                name: "TokenRefresh",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "TokenRefreshExpiere",
                table: "AspNetUsers");

            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "14400c1a-e155-4826-8ba5-1d4ea6c17ddc", "2", "User", "USER" },
                    { "40be5e6d-264f-49b1-a48e-cb0cb1add4f2", "1", "Admin", "ADMIN" },
                    { "f1cd1bc8-3894-4c9e-a143-bd16bd33956b", "3", "HR", "RRHH" }
                });
        }
    }
}
