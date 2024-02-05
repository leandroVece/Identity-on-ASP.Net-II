using System.Security.Claims;
using User.Management.Models;

namespace User.Management.Services;

public interface IUserServices
{

    public Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsyn(RegisterUser data);
    public Task<ApiResponse<List<string>>> AssingRoleToUserAsyn(AplicationUser user, List<string> roles);
    public Task<ApiResponse<string>> GetOtpLoginByAsyn(AplicationUser data, string password);
    public Task<ApiResponse<LoginResponse>> GetJWTTokenAsyn(AplicationUser data);
    public Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens);
    public Task<List<Claim>> AddClaimForUser(AplicationUser user);


}