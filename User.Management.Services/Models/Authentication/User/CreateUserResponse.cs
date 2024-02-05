using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace User.Management.Models;

public class CreateUserResponse
{
    public string Token { get; set; }
    public AplicationUser User { get; set; }
}