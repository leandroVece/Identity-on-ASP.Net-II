## ASP.Net Identity II

ESta es la segunda parte del tutorial sobre Identity y ASP.Net click para la [primera parte](https://github.com/leandroVece/Identity-on-ASP.Net-I). En esta parte comenzaremos refactorizando el codigo que hicimos.

Para esto comencemos instalando los paquetes que instalamos en nuestra protecyecto inicial a nuestra ClassList.

    <ItemGroup>
        <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="7.0.14" />
        <PackageReference Include="Microsoft.AspNetCore.Identity.EntityFrameworkCore" Version="7.0.14" />
        <PackageReference Include="Microsoft.EntityFrameworkCore.Sqlite" Version="7.0.14" />
        <PackageReference Include="Microsoft.EntityFrameworkCore.Tools" Version="7.0.14">
            <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
            <PrivateAssets>all</PrivateAssets>
        </PackageReference>
        <PackageReference Include="NETCore.MailKit" Version="2.1.0" />
    </ItemGroup>

## Refactorizacion del registro.

Como ya sabemos no es bueno delegar al controlador la tarea de concectarse a la base de datos. Para comenzar comencemos crearemos un nuevo modelo.

**./User.Management.Services/Models/ApiResponse.cs**

    public class ApiResponse<T>
    {
        public bool IsSucees {get;set;}
        public string Message {get;set;}
        public int Status {get;set;}
        public T Respose {get;set;}  
    }

Tambien mudaremos los modelos a nuestra classLib ya que en este lugar crearemos los servicios que consumiran nuestra base de datos. Luego crearemos un servicios que se encargue de conectar la base de datos relacionada con los usuarios y la aplicacion. Para esto vamos a crear una interfaz y un modelo que herede de esa interfaz. Comencemos con el primer punto que es el de registro.

**./User.Management.Services/Services/IUserServices.cs**

    public interface IUserServices{

        public Task<ApiResponse<string>> CreateUserWithTokenAsyn(RegisterUser data);

    }

**./User.Management.Services/Services/UserServices.cs**

    public class UserServices : IUserServices
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;

        
        public UserServices(
            UserManager<IdentityUser> userManager,RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager)
        {  
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }
        public async Task<ApiResponse<string>> CreateUserWithTokenAsyn(RegisterUser data)
        {
            //check User Exist
            var UserExist = await _userManager.FindByEmailAsync(data.Email);
            if (UserExist != null)
            {
                return new ApiResponse<string> { IsSucees = false, Status = 403, Message = "Usuario ya existe" };  
            }
            if (!await _roleManager.RoleExistsAsync(data.Role))
            {
                return new ApiResponse<string> { IsSucees = false, Status = 500 ,Message = "El rol no existe" };
            }

            //Add the User en the DB
            IdentityUser user = new IdentityUser(){
                    Email = data.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = data.UserName            
                };
            
            var result = await _userManager.CreateAsync(user, data.Password);
            if (result.Succeeded)
            { 
                //Assing a role
                await _userManager.AddToRoleAsync(user,data.Role);

                // //Add token verify the email

                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                return new ApiResponse<string> { IsSucees = true, Status = 201 , Respose = token,
                Message = "Usuario creado y correo de confirmacion enviado exitosamente" };
            }
            else{
                return new ApiResponse<string> { 
                    IsSucees = false, Status = 500 ,Message = "Error al crear el usuario: " + string.Join(", ", result.Errors.Select(e => e.Description)) };
            }             
        }
    }

Luego podemos probar si esto funciona. Para ello vamos a ir a nuestro archivo Program para agregar los nuevos servicios.

**./Identity II/program.cs**

    builder.Services.AddScoped<IUserServices,UserServices>();

Luego podemos ir a nuestro controlador para remplazar el nuevo codigo. Sin emabrgo hay algo que no tiene sentido en el codio mostrado. La tarea de agregar roles no deberia estar en un metodo que se encargan de registrar usuarios. Cada funcion tiene que Hacer lo que su nombre dice, por lo que antes de ir a nuestro controlador vamos a hacer un pqueño cambio. Para adaptar este cambio me gustaria comenzar creando una nueva clase que se adapte a este nueva clase de respuesta de nuestra api.

**./User.Management.Services/Models/User/CreateUserResponse.cs**

    public class CreateUserResponse
    {
        public string Token {get;set;}
        public IdentityUser User {get;set;}
    }

**./User.Management.Services/Services/IUserServices.cs**

    public interface IUserServices{

        public Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsyn(RegisterUser data);
        public Task<ApiResponse<List<string>>> AssingRoleToUserAsyn(IdentityUser user, List<string> roles);
    }

**./User.Management.Services/Services/UserServices.cs**

    public async Task<ApiResponse<List<string>>> AssingRoleToUserAsyn(IdentityUser user, List<string> roles)
    {
        var AssingRoles = new List<string>();
        foreach (var item in roles)
        {
            if (await _roleManager.RoleExistsAsync(item) && !await _userManager.IsInRoleAsync(user,item))
            {
                 await _userManager.AddToRoleAsync(user,item);
                 AssingRoles.Add(item);
            }
        }
        return new ApiResponse<List<string>> {IsSucees = true, Status = 200, Message = "Roles asignados correctamente", Respose = AssingRoles};
    }

    public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsyn(RegisterUser data)
    {
         //check User Exist
        var UserExist = await _userManager.FindByEmailAsync(data.Email);
        if (UserExist != null)
        {
            return new ApiResponse<CreateUserResponse> { IsSucees = false, Status = 403, Message = "Usuario ya existe" };  
        }

        //Add the User en the DB
        IdentityUser user = new IdentityUser(){
                Email = data.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = data.UserName            
            };
        
        var result = await _userManager.CreateAsync(user, data.Password);
        if (result.Succeeded)
        { 
            // //Add token verify the email

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

             return new ApiResponse<CreateUserResponse> { IsSucees = true, Status = 201 , Respose = new CreateUserResponse {Token = token, User = user},
             Message = "Usuario creado y correo de confirmacion enviado exitosamente" };
        }
        else{
             return new ApiResponse<CreateUserResponse> { 
                IsSucees = false, Status = 500 ,Message = "Error al crear el usuario: " + string.Join(", ", result.Errors.Select(e => e.Description)) };
        }             
    }

Ahora bien, aunque este codigo es un poco mas limpio todavia puede pulirse mas. No nos martilicemos con esos temas por ahora y veamos como quedaria nuestro controlador.

**Path: ./Identity II/Controller/AuthenticationController.CS**


    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] User.Management.Models.RegisterUser data){

        var CreateUserResponse = await _userService.CreateUserWithTokenAsyn(data);
        if (CreateUserResponse.IsSucees)
        {
            await _userService.AssingRoleToUserAsyn(CreateUserResponse.Respose.User,data.Roles);   
            var confirmationLink = Url.ActionLink(nameof(ConfirmEmail),"Authentication", new {CreateUserResponse.Respose.Token, email = data.Email});    
            var message = new Message(new string [] {data.Email!},"Confirmar Email por el link", confirmationLink!);
                _emailServisces.SendMail(message);

            return StatusCode(StatusCodes.Status200OK,
                        new Response { Status = "Success", Message = "Correo Enviado, por favor revice el buzon"});                 
        }

        return  StatusCode(StatusCodes.Status500InternalServerError,
            CreateUserResponse);

    }

Comenzamos poco a poco a ver otra estructura mas amigable y flexible que la que teniamos originalmente. Ai mismo nos damos cuenta que Identity es muy amigable y sensilla, compatible con tecnologias ya vistas antes en otros tutoriales. Al punto que solo una pequeña vista y explicacion basica bastarian para entender como usarlo.

## Refactorizacion de login

Cuando creamos nuestra funcion de login, hicimos 2 metodos diferente. Uno para un logueo sin la verificacion de 2 pasos y el otro con logueo de verificacion de 2 pasos. Si bien esto estaba bien, vemos que en nuestro codigo existia codigo duplicado, lo cual no es bueno.

Comencemos paso por paso para entender un poco como organizar mejor nuestro codigo. Si vamos a nuestros controlador lo primero que vemos es que este busca el ususario, comprueba y genera el token antes de realizar asignarle el rol y sus reclamos.

las dos acciones (login y login-2fa) comparten el codigo con lo referente al reclamo y el rol, por lo que eso podriamos separarlo. pero vamos con la parte superior de nuestra accion login.

**./User.Management.Services/Services/UserServices.cs**

En nuestro servicio vamos a agregar un nuevo metodo que generara el token de acceso.

    public async Task<ApiResponse<string>> GetOtpLoginByAsyn(IdentityUser data, string password)
    {
        await _signInManager.SignOutAsync();
        await _signInManager.PasswordSignInAsync(data.UserName, password, false, true);

        var token = await _userManager.GenerateTwoFactorTokenAsync(data, "Email");

        return new ApiResponse<string>
        {
            IsSucees = true,
            Status = 201,
            Respose = token,
            Message = "Usuario creado y correo de confirmacion enviado exitosamente"
        };

    }

>Recordatorio: recuerde agregar el metodo en la interfaz como corresponde. Creo ya que es inecesario agregar a cada nueva modificacion los metodos que la clase manejaria.

Con esta pequeña modificacion de codigo nuestra accion quedaria de la siguiente manera.

**Path: ./Identity II/Controller/AuthenticationController.CS**

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
                    new Response { Status = "Success", Message = "Enviado correo de confirmacion enviado exitosamente" });
            }
            if (await _userManager.CheckPasswordAsync(UserExist, data.Password))
            {
                //claimlist creation
                var authClaims = new List<Claim>{
                new Claim(ClaimTypes.Name,UserExist.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                //We add roles to the list
                var userRoles = await _userManager.GetRolesAsync(UserExist);
                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }
                //Generate the thoken the claims
                var jwt = GetToken(authClaims);
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwt),
                    expirations = jwt.ValidTo
                });
            }
        }
        return Unauthorized();
    }

Ahora podemos trabajar la parte inferior del codigo, mas especificamente en la parte de los reclamos (claim) ya que los dos tenian cidigo duplicado. Para esto solo necesitamos aplicar mas modulacion y como es parte de la administracion de los usuarios, este puede ir dentro de nuestro servicio.
**./User.Management.Services/Services/UserServices.cs**

    public async Task<List<Claim>> AddClaimForUser(IdentityUser user)
    {
        var authClaims = new List<Claim>{
                new Claim(ClaimTypes.Name,user.UserName!),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

        //We add roles to the list
        var userRoles = await _userManager.GetRolesAsync(user);
        foreach (var role in userRoles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, role));
        }

        return authClaims;
    }

Despues de separarlo ahora solo nos quedaria ocuparlo en nuestro controlador.

**Path: ./Identity II/Controller/AuthenticationController.CS**

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
                    new Response { Status = "Success", Message = "Enviado correo de confirmacion enviado exitosamente" });
            }
            if (await _userManager.CheckPasswordAsync(UserExist, data.Password))
            {
                var authClaims = await _userService.AddClaimForUser(UserExist);
                //Generate the thoken the claims
                var jwt = GetToken(authClaims);
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwt),
                    expirations = jwt.ValidTo
                });
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
            var authClaims = await _userService.AddClaimForUser(user);
            //Generate the thoken the claims

            var jwt = GetToken(authClaims);
            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(jwt),
                expirations = jwt.ValidTo
            });
        }
        return Unauthorized();
    }

Con esto poco a poco comenzamos a ver nuestro codigo un poco mas ordenado y amigable que antes. Con esto creo que he dado a entender mi punto y creo que para no hacer mas repetitivo dejare el resto de la refactorizacion a ustedes y vamos a ver un nuevo tema.

## Token refresh y campos de venciomientos a ApplicationUser

Si has estado en este mundo por un tiempo seguramente habras escuchado hablar del "token refresh" este token se creo con el fin de mejorar la experiencia del usuario y agregar una capa mas de seguridad a nuestro programa. Para entenderlo rapidamente pongamos un ejemplo sensillo.

Por lo general un token de acceso tiene una vida util mas corta que los token de actualización. Si un usuario por diversas razones comenzo a rellenar un formulario y este tuvo que salir por un tiempo, corre el peligro de que cuando vuelva para completarlo y enviarlo el token ya alla expirado. Esto seria terriblemente frustrante para el usuario.

¿Cual es la solucion? simplemente actualizar el token una vez este alla espirado. Con el uso de tokens de actualización, es posible implementar un flujo de renovación automática sin requerir la intervención del usuario. Cuando el token de acceso expira, la aplicación puede utilizar el token de actualización para obtener un nuevo token de acceso sin solicitar credenciales al usuario nuevamente.

Para hacer esto necesitamos almacenar en un lugar seguro este Token de actualizacion. Para ellos podemos crear 2 nuevos atributos en nuestras entidades usando una de los pilares de POO la herencia.

**./User.Management.ServicesModels/User/AplicationUser.cs**

    public class AplicationUser : IdentityUser
    {
        public string TokenRefresh { get; set; }
        public DateTime TokenRefreshExpiere { get; set; }
    }

Luego vamos a nuestro archivo DataBase donde generamos nuestra base de datos y indicamos que vamos a ser uso de estos nuevos atributos de la siguiete manera.

**./Identity II/Data/DataBase.cs**

    public class DataContext : IdentityDbContext<AplicationUser>
    {
        public DataContext(DbContextOptions<DataContext> options): base(options)
        { }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            SeedRoles(builder);
        }

        private static void SeedRoles(ModelBuilder builder){
            builder.Entity<IdentityRole>().HasData(
                new IdentityRole() { Name = "Admin", ConcurrencyStamp = "1", NormalizedName ="ADMIN"},
                new IdentityRole() { Name = "User", ConcurrencyStamp = "2", NormalizedName ="USER"},
                new IdentityRole() { Name = "HR", ConcurrencyStamp = "3", NormalizedName ="RRHH"}
            );
        }
    }

Como se puede ver a sumpple vista lo unico que cambia es que pasammos de heredar de **IdentityDbContext** a **IdentityDbContext<AplicationUser>** por todo lo demas se conservo como antes. El tultimo cambio que encesitamos hacer se encuentr en el archivo Program

**./Identity II/program.cs**

    //For Identity
    builder.Services.AddIdentity<AplicationUser, IdentityRole>()
        .AddEntityFrameworkStores<DataContext>()
        .AddDefaultTokenProviders();
    
Ahora para que todo esto funcione tendremos que cambiar todas aquellas instancias y llamadas en la que usabamos IdentityUser por AplicationUser. El funcionamiento no deberia cambiar ya que estamos aplicando el segundo principio de SOLID.

Para estas Alturas seguramente te estaras dando cuenta que hacer esto a hecho que nuestro codigo sea mas complicado de entender. Para hacerlo funcionar tendrias que usar una nomemclatura muy especifica debido a que tanto Models de nuestro proyecto principal y el model de nuestra classlib camparten los mismo objetos.

Este problema se llama problema de dependecia ciclica para solucionarlo lo unico que tendriamos que hacer seria crear una nueva capa (Classlib) para guardar estos servicios, modelos y demas. pero eso sera un tema para mas adelante por ahora solo busca tener una nomenclara parecida a esto.

    private readonly UserManager<User.Management.Models.AplicationUser> _userManager;
    private readonly SignInManager<User.Management.Models.AplicationUser> _signInManager;

>Nota: si prestas atencion a los anteriores ejemplos veras que nuestras clases que invocabamos desde nuestras ClassLib teniamos que llamarlos de la misma manera para que VSC pudiera saber con cual instancia estabamos trabajando. Sin embargo puedes "solucionarlo" eliminado las clases repetidas que estaban en nuestro proyecto principal.

![](./Identity%20II/img/Screenshot_1.png)

Ahora vamos a nuestro archivo program y vamos a agregar una linea mas de codigo.

**./Identity II/program.cs**

    builder.Services.AddAuthentication(op =>
    {
        op.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        op.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        op.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    }).AddJwtBearer(op =>
    {
        op.SaveToken = true;
        op.RequireHttpsMetadata = false;
        op.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = builder.Configuration["JWT:ValidAudience"],
            ValidIssuer = builder.Configuration["JWT:ValidIssuer"],
            ClockSkew = TimeSpan.Zero,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]))
        };
    });

ClockSkew = TimeSpan.Zero va a establecer que despues de que nuestro token se vencio ya no tendra valides, ya que le dimos una tolerancia de 0 segundos. Luego para hacerlo con buenas practicas vamos a ir a nuestro archivo appsetting para guardar el tiempo de vida de nuestro token.

**./Identity II/appsettings.cs**

    {
        ...
        "JWT": {
            "ValidAudience": "http://localhost:5218,https://localhost:7113,http://localhost:5218",
            "ValidIssuer": "http://localhost:5218,https://localhost:5218",
            "Secret": "EstaEsMiSuperLlavePrivadaQueNadiePuedeDecifrarQueTieneNumeritosMira12345",
            "ExpityTokenInMinutes": "30",
            "TokenRefreshInDays": "7"
        }
    }

Ahora podemos volver a nuestro controlador para crear una nueva accion privada donde generara una cadena aleatoria que servira como token refresh y a si mismo vamos a agregar el tiempo de expiracion desde el nuestra interfas _configure.

**Path: ./Identity II/Controller/AuthenticationController.CS**

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
                var authClaims = await _userService.AddClaimForUser(UserExist);

                updateTokenRefresh(UserExist);

                //Generate the thoken the claims
                var jwt = GetToken(authClaims);
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(jwt),
                    expirations = jwt.ValidTo
                });
            }
        }
        return Unauthorized();
    }

    private JwtSecurityToken GetToken(List<Claim> authClaims)
    {
        var authSingingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
        var Expiry = int.Parse(_configuration["JWT:ExpityTokenInMinutes"]);

        var token = new JwtSecurityToken(
            issuer: _configuration["JWT:ValidIssuer"],
            audience: _configuration["JWT:ValidAudience"],
            expires: DateTime.Now.AddMinutes(Expiry),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSingingKey, SecurityAlgorithms.HmacSha256)
        );
        return token;
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new Byte[64];
        using (var range = RandomNumberGenerator.Create())
        {
            range.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }

    private void updateTokenRefresh(AplicationUser user)
    {
        user.TokenRefresh = GenerateRefreshToken();
        var daysExpiry = int.Parse(_configuration["JWT:ExpityTokenInMinutes"]);
        user.TokenRefreshExpiry = DateTime.Now.AddDays(daysExpiry);

        _userManager.UpdateAsync(user);
    }

Como nosotros estamos guardando nuestro TokenRefresh en nuestra base de datos solo necesitamos actualizar los valores, algo que ya conociamos. como este token lo vamos a usar tanto en el logueo normal como el logueo con autenticacion de dos pasos seria bueno abtraer esta parte del codigo para evitar que nosotros repitamos codigo.

Ahora bien con esto solo tenemos la generacion de un nuevo codigo, poro todavia no lo hemos implementado. necesitamos hacer que nuestro programa sepa el token expiro verifique que nuestro tokenRefresh no este caducado y que emita un nuevo token de autorizacion.

Comencemos creando una clase que contengan a nuestros tokens y una clase que contenga nuestra respuesta de nuestra peticion de inicio de session.

**./User.Management.Services/Services/Models/TokenType.cs**

    namespace User.Management.Services;

    public class TokenType
    {
        public string Token { get; set; }
        public DateTime TimeExpiry { get; set; }

    }

**./User.Management.Services/Services/Models/Login/LoginResponse.cs**

    public class LoginResponse
    {
        public TokenType TokenAcces { get; set; }
        public TokenType TokenRefresh { get; set; }

    }

Con esto lo que devolveran nuestras acciones seria lo siguiente.

**Path: ./Identity II/Controller/AuthenticationController.CS**

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
                var authClaims = await _userService.AddClaimForUser(UserExist);
                //Generate the thoken the claims

                updateTokenRefresh(UserExist);

                var jwt = GetToken(authClaims);
                return Ok(new LoginResponse()
                {
                    TokenAcces = new()
                    {
                        Token = new JwtSecurityTokenHandler().WriteToken(jwt),
                        TimeExpiry = jwt.ValidTo
                    },
                    TokenRefresh = new()
                    {
                        Token = UserExist.TokenRefresh,
                        TimeExpiry = UserExist.TokenRefreshExpiry
                    }
                });
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
            var authClaims = await _userService.AddClaimForUser(user);
            //Generate the thoken the claims
            updateTokenRefresh(user);
            var jwt = GetToken(authClaims);
            return Ok(new LoginResponse()
            {
                TokenAcces = new()
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(jwt),
                    TimeExpiry = jwt.ValidTo
                },
                TokenRefresh = new()
                {
                    Token = user.TokenRefresh,
                    TimeExpiry = user.TokenRefreshExpiry
                }
            });
        }
        return Unauthorized();
    }

![](./Identity%20II/img/Screenshot_2.png)

Como se puede notar esto tiene codigo repetido, esto en parte se debe a que no usamos servicios aparte para generar el token o el email de confirmacion. Si lo hacemos podemos llamar a estos servicios desde nuestro userServicios para evitar esta duplicado de codigo y a su vez terminar de delegar todas las responsabilidades sobre la administracion de usuario a nuestro servicio.

Para simular este comportamiento y poder refactorizar vamos a mover aquellas funciones privadas que teniamos en nuestro controlador a nuestro servicios de usuarios (menos el que usamos para enviar un email de confirmacion). Luego en nuestro servicios agregaremos una nueva accion que generaria los reclamos y token.

**./User.Management.Services/Services/UserServices.cs**

    public async Task<ApiResponse<LoginResponse>> GetJWTTokenAsyn(AplicationUser data)
    {
        var authClaims = await AddClaimForUser(data);
        if (data.TokenRefreshExpiry <= DateTime.Now)
        {
            updateTokenRefresh(data);
        }

        //Generate the thoken the claims 
        var jwt = GetToken(authClaims);
        return new ApiResponse<LoginResponse>
        {
            Respose = new LoginResponse
            {
                TokenAcces = new()
                {
                    Token = new JwtSecurityTokenHandler().WriteToken(jwt),
                    TimeExpiry = jwt.ValidTo
                },
                TokenRefresh = new()
                {
                    Token = data.TokenRefresh,
                    TimeExpiry = data.TokenRefreshExpiry
                }
            },
            IsSucees = true,
            Status = 200,
            Message = $"Token created"
        };
    }

Nuestras acciones quedarian de esta manera.

**Path: ./Identity II/Controller/AuthenticationController.CS**

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

Esto remarca nuevamanete la necesidad de las buenas practicas y de entender que tipo de arquitectura debemos utilizar para nuestro trabajo. Como siempre pienso que pasar por estos problemas nos ayudan a entender mejor la importancia de tener un codigo limpio y ordenado. Ahora veamos si esto funcionoa realmente.

![](./Identity%20II/img/Screenshot_3.png)


Ahora solo nos queda acceder de nuevo con el tokenRefresh. Para ello en nuestro controlador solo tendremos que agregar una nueva accion.

**Path: ./Identity II/Controller/AuthenticationController.CS**

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

Y un nuevo metodo en nuestro servicios de usuarios.

**./User.Management.Services/Services/UserServices.cs**

    public async Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens)
    {

        var accessToken = tokens.TokenAcces;
        var refreshToken = tokens.TokenRefresh;
        var principal = GetClaimsPrincipal(accessToken.Token);
        var user = await _userManager.FindByNameAsync(principal.Identity.Name);
        if (refreshToken.Token != user.TokenRefresh && refreshToken.TimeExpiry <= DateTime.Now)
        {
            return new ApiResponse<LoginResponse>
            {
                IsSucees = false,
                Status = 400,
                Message = $"Token invalid or expired"
            };
        }
        var response = await GetJWTTokenAsyn(user);
        return response;
    }

Este método se encarga de validar un token de acceso JWT utilizando las configuraciones especificadas en TokenValidationParameters y devuelve un ClaimsPrincipal que representa al usuario autenticado, incluyendo las reclamaciones (claims) extraídas del token.

>Recordatorio: Si ustedes desean probar esto, lo mejor seria cambiar el tiempo de nuestra variable **ExpityTokenInMinutes** de nuestro archivo appssettings a 1, de esa maenra podran probar si funciona despues de un minuto. sin embargo se puede probar directamente ya que no validamos en ningun momento si el token estaba vencido o no.