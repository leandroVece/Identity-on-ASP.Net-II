using System.ComponentModel.DataAnnotations;

namespace User.Management.Models;

public class LoginUser
{
    [Required]
    public string UserName {get;set;}
    [Required]
    public string Password {get;set;}
}