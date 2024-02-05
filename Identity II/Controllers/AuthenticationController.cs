using Microsoft.AspNetCore.Mvc;
using User.Management.Models;
using Microsoft.AspNetCore.Identity;
using User.Management.Services;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using System.ComponentModel.DataAnnotations;
using Identity_II.Models;
using System.Security.Cryptography;


namespace Identity_II.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthenticationController : ControllerBase
{
    private readonly UserManager<User.Management.Models.AplicationUser> _userManager;
    private readonly SignInManager<User.Management.Models.AplicationUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IEmailServices _emailServisces;
    private readonly IConfiguration _configuration;
    private readonly IUserServices _userService;

    public AuthenticationController(
        UserManager<User.Management.Models.AplicationUser> userManager, RoleManager<IdentityRole> roleManager, IEmailServices emailServisces,
        SignInManager<User.Management.Models.AplicationUser> signInManager, IConfiguration configuration, IUserServices userService)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _emailServisces = emailServisces;
        _configuration = configuration;
        _signInManager = signInManager;
        _userService = userService;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] User.Management.Models.LoginUser data)
    {
        //check User Exist
        var UserExist = await _userManager.FindByNameAsync(data.UserName);

        //confirm Two Factory
        if (UserExist != null)
        {
            if (UserExist.TwoFactorEnabled)
            {
                var token = await _userService.GetOtpLoginByAsyn(UserExist, data.Password);
                var message = new Message(new string[] { UserExist.Email! }, "Confirmar Email por el link", token.Respose);
                _emailServisces.SendMail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Models.Response { Status = "Success", Message = "Enviado correo de confirmacion enviado exitosamente" });
            }
            if (await _userManager.CheckPasswordAsync(UserExist, data.Password))
            {
                var response = await _userService.GetJWTTokenAsyn(UserExist);

                return Ok(response);
            }
        }
        return Unauthorized();
    }

    [HttpPost("login-2fa")]
    public async Task<IActionResult> Login2FA(string token, string username)
    {
        var user = await _userManager.FindByNameAsync(username);
        var sign = await _signInManager.TwoFactorSignInAsync("Email", token, false, false);

        if (sign.Succeeded && user != null)
        {
            var response = await _userService.GetJWTTokenAsyn(user);

            return Ok(response);
        }
        return Unauthorized();
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken(LoginResponse tokens)
    {
        var jwt = await _userService.RenewAccessTokenAsync(tokens);
        if (jwt.IsSucees)
        {
            return Ok(jwt);
        }
        return StatusCode(StatusCodes.Status404NotFound,
                    new Models.Response { Status = "Success", Message = "codigo invalido" });
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] User.Management.Models.RegisterUser data)
    {

        var CreateUserResponse = await _userService.CreateUserWithTokenAsyn(data);
        if (CreateUserResponse.IsSucees)
        {
            await _userService.AssingRoleToUserAsyn(CreateUserResponse.Respose.User, data.Roles);
            var confirmationLink = Url.ActionLink(nameof(ConfirmEmail), "Authentication", new { CreateUserResponse.Respose.Token, email = data.Email });
            var message = new Message(new string[] { data.Email! }, "Confirmar Email por el link", confirmationLink!);
            _emailServisces.SendMail(message);

            return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Correo Enviado, por favor revice el buzon" });
        }

        return StatusCode(StatusCodes.Status500InternalServerError,
            CreateUserResponse);

    }


    [HttpGet("ConfirmEmail")]
    public async Task<ActionResult> ConfirmEmail(string token, string email)
    {

        var User = await _userManager.FindByEmailAsync(email);
        if (User != null)
        {
            var result = await _userManager.ConfirmEmailAsync(User, token);
            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Correo confirmado" });
            }
        }
        return StatusCode(StatusCodes.Status500InternalServerError,
            new Response { Status = "Error", Message = "El usuario no Existe" });

    }

    [HttpPost("Forgot-password")]
    [AllowAnonymous]
    public async Task<ActionResult> ForgoPassword([Required] string email)
    {

        var user = await _userManager.FindByEmailAsync(email);
        if (user != null)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);

            var confirmationLink = Url.ActionLink(nameof(ResetPasword), "Authentication", new { token, email = user.Email });

            var message = new Message(new string[] { user.Email! }, "Restablecer contraseña", confirmationLink!);
            _emailServisces.SendMail(message);

            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Por favor verifique su correo" });
        }

        return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Error", Message = "El correo no existe" });

    }

    [HttpPost("reset-password")]
    [AllowAnonymous]
    public async Task<ActionResult> ResetPasword(PaswordReset data)
    {
        var user = await _userManager.FindByEmailAsync(data.Email);
        if (user != null)
        {
            var reset = await _userManager.ResetPasswordAsync(user, data.Token, data.Password);
            if (!reset.Succeeded)
            {
                foreach (var error in reset.Errors)
                {
                    ModelState.AddModelError(error.Code, error.Description);
                }
                return Ok(ModelState);
            }
            return StatusCode(StatusCodes.Status200OK,
                new Response { Status = "Success", Message = "Correo Enviado, por favor revice el buzon" });
        }
        return StatusCode(StatusCodes.Status500InternalServerError,
            new Response { Status = "Error", Message = "El usuario no Existe" });

    }

    [HttpGet]
    public async Task<ActionResult> testEmail()
    {
        var message = new Message(new string[] { "loelvece@gmail.com" }, "Test", "<h1>Testing...</h1>");
        _emailServisces.SendMail(message);
        return StatusCode(StatusCodes.Status200OK,
                   new Response { Status = "Success", Message = "Correo Enviado, por favor revice el buzon" });
    }



}
