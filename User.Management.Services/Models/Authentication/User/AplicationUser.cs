using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace User.Management.Models;

public class AplicationUser : IdentityUser
{
    public string TokenRefresh { get; set; }
    public DateTime TokenRefreshExpiry { get; set; }
}