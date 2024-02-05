using System.ComponentModel.DataAnnotations;

namespace User.Management.Models;

public class loginUserTwoFactoery
{
    [Required]
    public string email {get;set;}
    public bool TowFactory {get;set;}
}