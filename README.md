# ASP.NET Core Identity

## DEMO 1: Adding Identity to ASP.NET Core API Project

1. Add new API Project called "IdentityDemo"
2. Open project.json
3. Add the following under dependencies

```javascript
"Microsoft.AspNetCore.Identity": "1.0.1",
"Microsoft.AspNetCore.Identity.EntityFrameworkCore": "1.0.1",
"Microsoft.EntityFrameworkCore.SqlServer": "1.0.1",
"Microsoft.EntityFrameworkCore.Tools": "1.0.0-preview2-final"
```
4. Add the following to "tools" section after "dependencies"
```javascript
"Microsoft.EntityFrameworkCore.Tools": {
    "version": "1.0.0-preview2-final",
    "type": "build"
} 
```
5. Add the folders "Membership/Models"
    1. In Models folder Add new class ApplicationUser that extends IdentityUser and adds three custom properties to user model.

```c#
namespace IdentityDemo.Membership
{
    public class ApplicationUser : IdentityUser
    {
        [StringLength(50)]
        public string FirstName { get; set; }

        [StringLength(50)]
        public string LastName { get; set; }

        [StringLength(50)]
        public string Department { get; set; }
    }
}
```
6. In Membership folder add new class MembershipDbContext that extends IdentityDbContext

```c#
namespace IdentityDemo.Membership
{
    public class MembershipDbContext : IdentityDbContext
    {
        public MembershipDbContext(DbContextOptions options):base(options)
        {
        
        }
        
        public DbSet<ApplicationUser> ApplicationUsers { get; set; }
    }
}
```
7. Open Startup.cs class and add the following services in Configuration method.
```c#
services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<MembershipDbContext>()
    .AddDefaultTokenProviders();

services.AddDbContext<MembershipDbContext>(options =>
{
    options.UseSqlServer(Configuration["Data:ConnectionString"]);
});
```
The first section tells ASP.NET that Identity is being added and to use the ApplicationUser and Entity Framework to store the identity model.

The second section adds the MembershipDbContext to the service container and to use SQL Server.

8. In the Configure method of Startup.cs add the following before app.UseMvc()
```C#
app.UseIdentity();
```

9. Open the appsettings.json file and add the following after the Logging section.
```javascript
  "Data": {
    "ConnectionString": "Data Source=(localdb)\\MSSQLLocalDB;Initial Catalog=IdentityDemo;Integrated Security=True;Connect Timeout=30;Encrypt=False;TrustServerCertificate=True;ApplicationIntent=ReadWrite;MultiSubnetFailover=False"
  }
```
10. Now we need to seed the database. In Membership folder add a new class named InitMembership and add the following code.
```c#
namespace IdentityDemo.Membership
{
    public class InitMembership
    {
        private RoleManager<IdentityRole> _roleManager;
        private UserManager<ApplicationUser> _userManager;


        public InitMembership(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task Seed(bool rest)
        {
            if (rest)
            {
                await ResetDatabase();
            }
            await AddRoles("Staff", "Manager");

            await AddUser("asmith", "A", "Smith", "asmith@fakecompany.com", "Sales", "Staff");
            await AddUser("djones", "D", "Jones", "djones@fakecompany.com", "Sales", "Manager");
            await AddUser("bjohnson", "B", "Johson", "bjohnson@fakecompany.com", "IT", "Staff");
            await AddUser("cwilliams", "C", "Williams", "cwilliams@fakecompany.com", "IT", "Manager");
            
        }

        public async Task AddRoles(params string[] roles)
        {
            foreach (var roleName in roles)
            {
                if (!(await _roleManager.RoleExistsAsync(roleName)))
                {
                    var role = new IdentityRole(roleName);
                    await _roleManager.CreateAsync(role);
                }
            }
        }

        public async Task ResetDatabase()
        {
            var roles = await _roleManager.Roles.ToListAsync();
            foreach (var identityRole in roles)
            {
                await _roleManager.DeleteAsync(identityRole);
            }

            var users = await _userManager.Users.ToListAsync();
            foreach (var widgetUser in users)
            {
                await _userManager.DeleteAsync(widgetUser);
            }
        }

        public async Task AddUser(
            string userName,
            string firstName,
            string lastName,
            string email,
            string department,
            string role)
        {
            var user = await _userManager.FindByNameAsync(userName);

            if (user != null) return;

            user = new ApplicationUser()
            {
                UserName = userName,
                FirstName = firstName,
                LastName = lastName,
                Department = department,
                Email = email
            };

            var userResult = await _userManager.CreateAsync(user, "AbCd!234");
            if (!userResult.Succeeded)
            {
                throw new InvalidOperationException($"Unable to add user {firstName} {lastName}");
            }

            if (!string.IsNullOrEmpty(role) && (await _roleManager.RoleExistsAsync(role)))
            {
                var roleResult = await _userManager.AddToRoleAsync(user, role);
                if (!roleResult.Succeeded)
                {
                    throw new InvalidOperationException($"Unable to add role {role} to user {firstName} {lastName}");
                }
            }
        }
    }
}
```
11. In Startup.cs ConfigureServices method add the following at the end.
```c#
services.AddTransient<InitMembership>();
```
12. Update the Configure method by adding a InitMembership parameter and adding a call to the Seed method at the end. After the change the method should look like:
```c#
public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory, InitMembership initMembership)
{
    loggerFactory.AddConsole(Configuration.GetSection("Logging"));
    loggerFactory.AddDebug();

    app.UseIdentity();

    app.UseMvc();

    initMembership.Seed(true).Wait();
}
```
13. Open a command prompt to the project's folder and use the following commands build the database
```
dotnet ef migrations add AddIdentitySupport
```
```
dotnet ef database update
```
14. Run the application to launch the site and seed the database.
```
dotnet run
```


## DEMO 2: Adding Authentication Support
1. Add a Models folder to the project root and 
2. In the Models folder add a new class named "Credentials.cs", and add the following:
```c#
namespace IdentityDemo.Models
{
    public class Credentials
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
```
3. Add a new Controller class to the Controller folder named "AuthController.cs".
4. Add the following code:
```c#
namespace IdentityDemo.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly ILogger<AuthController> _logger;
        private readonly UserManager<WidgetUser> _userManager;
        private readonly IPasswordHasher<WidgetUser> _passwordHasher;
        private readonly IConfigurationRoot _configuration;

        public AuthController(
            ILogger<AuthController> logger,
            UserManager<WidgetUser> userManager,
            IPasswordHasher<WidgetUser> passwordHasher,
            IConfigurationRoot configuration)
        {
            _logger = logger;
            _userManager = userManager;
            _passwordHasher = passwordHasher;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] Credentials credentials)
        {
            try
            {
                var result = await _signInManager.PasswordSignInAsync(credentials.UserName, credentials.Password, false,
                    false);
                if (result.Succeeded)
                {
                    return Ok();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message, ex.StackTrace);
            }

            return BadRequest("Login Failed");
        }
    }
}
```
5. Open the ValuesController.cs and add the [Authorize] attribute to the class. Should look like the following.
```c#
    [Route("api/[controller]")]
    [Authorize]
    public class ValuesController : Controller
```
6. Open Startup.cs and add the following as the first line in the  method.
```c#
services.AddSingleton(Configuration);
```
7. Then add the follow to ConfigureServices method before services.addMvc():
```c#
services.Configure<IdentityOptions>(options =>
{
    options.Cookies.ApplicationCookie.Events =
    new CookieAuthenticationEvents()
    {
        OnRedirectToLogin = (context) =>
        {
            if (context.Response.StatusCode == 200)
            {
                context.Response.StatusCode = 401;
            }

            return Task.CompletedTask;
        },
        OnRedirectToAccessDenied = (context) =>
        {
            if (context.Response.StatusCode == 200)
            {
                context.Response.StatusCode = 403;
            }

            return Task.CompletedTask;
        }
    };
});
```
By default Identity will redirect to the a login page which does not exist in an API. The above code simply adds handlers for the Application Cookie events for redirecting and just return standard status codes.

8. Using Postman to test Login and Values

## DEMO 3: Adding JWT to ASP.NET API Project
1. Open project.json and add the following to dependencies:
```
"Microsoft.AspNetCore.Authentication.JwtBearer": "1.0.1",
"System.IdentityModel.Tokens.Jwt": "5.1.2"
```
2. Open Startup.cs and add the following before app.UseIdentity() in the Configure Method.
```c#
app.UseJwtBearerAuthentication(new JwtBearerOptions()
{
    AutomaticAuthenticate = true,
    AutomaticChallenge = true,
    
    TokenValidationParameters = new TokenValidationParameters()
    {
        ValidIssuer = Configuration["Tokens:Issuer"],
        ValidAudience = Configuration["Tokens:Audience"],
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Tokens:Key"])),
        ValidateLifetime = true
    }
});
```
3. Open appsettings.json and add the following after "Data":
```
  "Tokens": {
    "Key": "CyAFooBarQuuxIsTheStandardTypeOfStringWeUse12345",
    "Issuer": "http://fakecompany.io",
    "Audience": "http://fakecompany.io"
  }
```  
4. Open the AuthController.cs and add the following method:
```c#
[HttpPost]
[Route("token")]
public async Task<IActionResult> CreateToken([FromBody]Credentials credentials)
{
    try
    {
        var user = await _userManager.FindByNameAsync(credentials.UserName);
        if (user != null)
        {
            if (_passwordHasher.VerifyHashedPassword(user, user.PasswordHash, credentials.Password) ==
                PasswordVerificationResult.Success)
            {
                var userClaims = await _userManager.GetClaimsAsync(user);
                var claims = new[]
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.GivenName, user.FirstName),
                    new Claim(JwtRegisteredClaimNames.FamilyName, user.LastName),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim("department", user.Department),
                }.Union(userClaims);

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Tokens:Key"]));
                var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: _configuration["Tokens:Issuer"],
                    audience: _configuration["Tokens:Audience"],
                    claims: claims,
                    expires: DateTime.UtcNow.AddMinutes(30),
                    signingCredentials: signingCredentials);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expirations = token.ValidTo
                });
            }
        }
    }
    catch (Exception ex)
    {
        _logger.LogError(ex.Message, ex.StackTrace);
    }

    return BadRequest("Token Creation Failed");
}
```

## DEMO 4: Applying Authorization
1. Add a new class named "Document.cs" to Models folder with the following code:
```c#
namespace IdentityDemo.Models
{
    public class Document
    {
        public Document()
        {
            
        }

        public Document(int id, string content, string department, string owner, bool managerOnly)
        {
            Id = id;
            Content = content;
            Department = department;
            Owner = owner;
            ManagerOnly = managerOnly;
        }

        public int Id { get; set; }

        [Required]
        public string Content { get; set; }

        [Required]
        public string Department { get; set; }

        public string Owner { get; set; }
        public bool ManagerOnly { get; set; }
    }
}
```
2. Add a new Controller named "DocumentsController.cs" with the following code:
```c#
namespace IdentityDemo.Controllers
{
    [Route("api/[controller]")]
    public class DocumentsController : Controller
    {
        private ILogger<DocumentsController> _logger;

        public DocumentsController(ILogger<DocumentsController> logger)
        {
            _logger = logger;
        }

        [HttpGet]
        [Route("")]
        public IActionResult GetPublicDocuments()
        {
            _logger.LogInformation("Public Documents were accessed.");
            var result = GetDocuments().Where(p => p.Department == "All" && !p.ManagerOnly);

            return Ok(result);
        }

        [HttpGet]
        [Route("{id:int}")]
        public IActionResult GetPublicDocument(int id)
        {
            _logger.LogInformation("Public Documents were accessed.");

            var result = GetDocuments().FirstOrDefault(d=>d.Id==id);

            if (result == null)
            {
                return NotFound();
            }

            return Ok(result);
        }

        [HttpGet]
        [Route("managers")]
        public IActionResult GetManagerDocuments()
        {
            _logger.LogInformation("Manager Documents were accessed.");
            var result = GetDocuments()
                .Where(p=>p.ManagerOnly);

            return Ok(result);
        }

        [HttpGet]
        [Route("department/{id}")]
        public IActionResult GetByDepartment(string id)
        {
            _logger.LogInformation($"{id} Documents were accessed.");

            var result = GetDocuments()
                .Where(p => p.Department.Equals(id,StringComparison.CurrentCultureIgnoreCase) && !p.ManagerOnly);

            return Ok(result);
        }

        [HttpPost]
        public IActionResult CreateDepartmentDocument([FromBody] Document model)
        {


            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            model.Id = GetDocuments().Count() + 1;
            model.Owner = User.FindFirstValue(ClaimTypes.NameIdentifier);

            _logger.LogInformation("Document created");

            return Ok(model);
        }

        [HttpPut]
        [Route("{id:int}")]
        public IActionResult UpdateDeparmentDocument(int id, [FromBody] Document model)
        {
            var payload = GetDocuments().FirstOrDefault(p => p.Id == id);
            if (payload == null)
            {
                return NotFound();
            }

            payload.Content = model.Content;
            payload.Department = model.Department;
            payload.ManagerOnly = model.ManagerOnly;
            payload.Owner = User.FindFirstValue(ClaimTypes.NameIdentifier);

            _logger.LogInformation("Document Modified");
            return Ok(payload);
        }

        private List<Document> GetDocuments()
        {
            return new List<Document>()
            {
                new Document(1, "Public Document 1", "All", "cwilliams", false),
                new Document(2, "Public Document 2", "All", "djones", false),
                new Document(3, "Manager Document 1", "All", "djones", true),
                new Document(4, "Manager Document 2", "IT", "cwilliams", true),
                new Document(5, "Sales Document 1", "Sales", "asmith", false),
                new Document(6, "IT Document 1", "IT", "bjohnson", false),
            };
        }
    }
}
```
3. Test API endpoints with PostMan.
4. Add [Authorize] attribute to DocumentsController. Should look like below.
```c#
[Route("api/[controller]")]
[Authorize]
public class DocumentsController : Controller
{
    ... Rest of class
}
```
5. Log In with Staff account and test endpoints again.