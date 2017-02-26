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
11. In Startup.cs ConfigureService method add the following at the end.
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
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ILogger<AuthController> _logger;

        public AuthController(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, ILogger<AuthController> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = logger;
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
6. Open Startup.cs class and add the follow to ConfigureServices method:
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

7. Using Postman to test Login and Values