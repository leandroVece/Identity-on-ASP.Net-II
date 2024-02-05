
namespace User.Management.Services;

public class LoginResponse
{
    public TokenType TokenAcces { get; set; }
    public TokenType TokenRefresh { get; set; }

}