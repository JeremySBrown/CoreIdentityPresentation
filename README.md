# ASP.NET Core Identity
## Overview
This presentation provides an overview of ASP.NET Core Identity and will demonstrate how to secure an ASP.NET Core API project using Identity and JSON Web Tokens.

## Sample Application and Demos

The latest LTS version of .NET Core was used for the sample application. You can install it from [https://dot.net](https://dot.net). 

You can either clone the sample application from this repo or can you build it following the rest of this document.

Clone the main repo:
```
git clone https://github.com/TRINUG-Meetup/ASP_NET_Core_Sig.git
```
Navigate to the folder ASP_NET_Core_Sig/Session3/Identity/IdentityDemo/

Open a command line to the root of the project and using the following commands to build the application.

Restore packages
```
dotnet restore
```
Build and Create Database
```
dotnet ef database update
```
You can launch the application from Visual Studio or from the command line using:
```
dotnet run
```

### Postman
During the presentation I'll be using POSTMAN to test the API endpoints. You can install it from:
[https://www.getpostman.com/](https://www.getpostman.com/)

Once installed you can import the collection I used to test the application. The import file ```IdentityDemo.postman_collection.json``` can be found in the project's root folder 

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
Also to keep EF Core happy change the version of ```Microsoft.Extensions.Logging``` to ```1.0.1```
```javascript
"Microsoft.Extensions.Logging": "1.0.1",
```
Add the following to "tools" section after "dependencies"
```javascript
"Microsoft.EntityFrameworkCore.Tools": {
    "version": "1.0.0-preview2-final",
    "type": "build"
} 
```
Add the folders "Membership/Models"
In Models folder Add new class ApplicationUser that extends IdentityUser and adds three custom properties to user model.

```c#
namespace IdentityDemo.Membership.Models
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
In Membership folder add new class MembershipDbContext that extends IdentityDbContext

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
Open Startup.cs class and add the following services in Configuration method.
```c#
services.AddSingleton(Configuration);

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

In the Configure method of Startup.cs add the following before app.UseMvc()
```C#
app.UseIdentity();
```

Open the appsettings.json file and add the following after the Logging section.
```javascript
  "Data": {
    "ConnectionString": "Data Source=(localdb)\\MSSQLLocalDB;Initial Catalog=IdentityDemo;Integrated Security=True;Connect Timeout=30;Encrypt=False;TrustServerCertificate=True;ApplicationIntent=ReadWrite;MultiSubnetFailover=False"
  }
```

Now we need to seed the database. In Membership folder add a new class named InitMembership and add the following code.

```c#
namespace IdentityDemo.Membership
{
    public class InitMembership
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;

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
            await AddUser("emiller", "E", "Miller", "emiller@fakecompany.com", "", "Intern");
            
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
In Startup.cs ConfigureServices method add the following at the end.
```c#
services.AddTransient<InitMembership>();
```
Update the Configure method by adding a InitMembership parameter and adding a call to the Seed method at the end. After the change the method should look like:
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
Open a command prompt to the project's folder and use the following commands build the database
```
dotnet restore
```
```
dotnet ef migrations add AddIdentitySupport
```
```
dotnet ef database update
```
Run the application to launch the site and seed the database.
```
dotnet run
```


## DEMO 2: Adding Authentication Support
- Add a Models folder to the project root and 
- In the Models folder add a new class named "Credentials.cs", and add the following:
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
- Add a new Controller class to the Controller folder named "AuthController.cs".
- Add the following code:
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
        private readonly IConfigurationRoot _configuration;
        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;

        public AuthController(
             SignInManager<ApplicationUser> signInManager,
             UserManager<ApplicationUser> userManager,
             RoleManager<IdentityRole> roleManager,
             ILogger<AuthController> logger,
             IConfigurationRoot configuration,
             IPasswordHasher<ApplicationUser> passwordHasher)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _logger = logger;
            _configuration = configuration;
            _passwordHasher = passwordHasher;
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
 Open the ValuesController.cs and add the [Authorize] attribute to the class. Should look like the following.
```c#
    [Route("api/[controller]")]
    [Authorize]
    public class ValuesController : Controller
```
 Open Startup.cs and add the following as the first line in the  method.
```c#
services.AddSingleton(Configuration);
```
Then add the follow to ConfigureServices method before services.addMvc():
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

Use Postman to test Login and Values

## DEMO 3: Adding JWT to ASP.NET API Project
Open project.json and add the following to dependencies:
```
"Microsoft.AspNetCore.Authentication.JwtBearer": "1.0.1",
"System.IdentityModel.Tokens.Jwt": "5.1.2"
```
Open Startup.cs and add the following before app.UseIdentity() in the Configure Method.
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
Open appsettings.json and add the following after "Data":
```
  "Tokens": {
    "Key": "123This!Is!The!Secret!String!T0!Secure!Your!Tokens456",
    "Issuer": "http://fakecompany.io",
    "Audience": "http://fakecompany.io"
  }
```  
Open the AuthController.cs and add the following method:
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
                // Get Existing User Claims
                var userClaims = await _userManager.GetClaimsAsync(user);

                // Add Claims from WidgetUser
                var claims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.GivenName, user.FirstName),
                    new Claim(JwtRegisteredClaimNames.FamilyName, user.LastName),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                };
                if (!string.IsNullOrEmpty(user.Department))
                {
                    claims.Add(new Claim("Department",user.Department));
                }

                // Add Roles the User Belongs To
                var roles = await _userManager.GetRolesAsync(user);
                foreach (var role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }

                // Combined existing claims with new
                claims = claims.Union(userClaims).ToList();

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
        return StatusCode(StatusCodes.Status500InternalServerError, ex);
    }

    return BadRequest("Token Creation Failed");
}
```

You may need to clear your cookies and restart Chrome and Postman or token authentication won't work as expected because ASP.NET will validate the cookie token first and authorize the user giving false positive results for the next section.

## DEMO 4: Applying Authorization
Add a new class named "Document.cs" to Models folder with the following code:
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
Add a new Controller named "DocumentsController.cs" with the following code:
```c#
namespace IdentityDemo.Controllers
{
    [Route("api/[controller]")]
    public class DocumentsController : Controller
    {
        private readonly ILogger<DocumentsController> _logger;
        private readonly IAuthorizationService _authorizationService;


        public DocumentsController(ILogger<DocumentsController> logger, IAuthorizationService authorizationService)
        {
            _logger = logger;
            _authorizationService = authorizationService;
        }

        [HttpGet]
        [Route("")]
        public IActionResult GetPublicDocuments()
        {
           _logger.LogInformation("Public Documents were accessed.");
            
            var documents = GetDocuments()
                .Where(p => p.Department == "All" && !p.ManagerOnly);

            return Ok(documents);
        }

        [HttpGet]
        [Route("{id:int}")]
        public IActionResult GetDocument(int id)
        {
            _logger.LogInformation($"Public Document {id} were accessed.");

            var result = GetDocuments().FirstOrDefault(d => d.Id == id);

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

            var documents = GetDocuments()
                .Where(p => p.ManagerOnly);

            return Ok(documents);
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
            var document = GetDocuments().FirstOrDefault(p => p.Id == id);
            if (document == null)
            {
                return NotFound();
            }

            document.Content = model.Content;
            document.Department = model.Department;
            document.ManagerOnly = model.ManagerOnly;
            document.Owner = User.FindFirstValue(ClaimTypes.NameIdentifier);

            _logger.LogInformation("Document Modified");
            return Ok(document);
        }

        [HttpDelete]
        [Route("{id:int}")]        
        public IActionResult DeleteDocument(int id)
        {
            _logger.LogInformation("Public Documents were accessed.");

            var document = GetDocuments().FirstOrDefault(d => d.Id == id);

            if (document == null)
            {
                return NotFound();
            }

            return StatusCode(StatusCodes.Status202Accepted);
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
                new Document(7, "IT Document 1", "IT", "bjohnson", false),
                new Document(8, "IT Document 2", "IT", "cwilliams", false),
            };
        }
    }
}
```
- Run Wide Open API Calls in Postman. Should get 200s
- Add [Authorize] attribute to DocumentsController. Should look like below.
```c#
[Route("api/[controller]")]
[Authorize]
public class DocumentsController : Controller
{
    ... Rest of class
}
```
- Rerun Wide Open API Calls in Postman. Should get 401s
- Login with "Intern" User Account, and test Get Documents API call


## Enforcing Policies on Document API
The Document Controller is now setup to only allow authenticated users, but that is not enough because any authenticated user can perform CRUD operations on documents and Read documents only permitted to managers.

Below are 6 requirements that need to be applied to the Document Controller. We'll use a combination of Roles, Claims and Policies to achieve this.

1. Only members of the Staff and Manager roles can access API
2. Only Managers can view documents flagged as Manager Only.
3. Only Managers of the IT Department can delete documents.
4. Members can only view documents from their department or flagged as All.
5. Members can create documents for their departments or All.
6. Documents can only be modified by owners or department managers.

### Only members of the Staff and Manager roles can access API &amp; Only Managers can view documents flagged as Manager Only.
Change [Authorize] attribute to:
```c#
[Authorize(Roles="Staff,Manager")]
```
Change GetManagerDocuments method to:
```c#
[HttpGet]
[Route("managers")]
[Authorize(Roles="Manager")]
public IActionResult GetManagerDocuments()
```
Test results in Postman

Applying Roles to the Authorize attribute on classes and actions is nothing new to ASP.NET, but now the same thing can be achieved with policies.

Open the Startup.cs class and add the following after ```services.AddMvc();```
```c#
services.AddAuthorization(options =>
{
    options.AddPolicy("SalesAndITOnly", policy=> policy.RequireClaim("Department", "Sales", "IT"));
    options.AddPolicy("ManagersOnly", policy=> policy.RequireRole("Manager"));
});
```
Replace the class Authorize attribute with:
```c#
[Authorize(Policy = "SalesAndITOnly")]
```
Replace the GetManagerDocuments() Authorize attribute with:
```c#
[Authorize(Policy= "ManagersOnly")]
```
Test in Postman to make sure you get the same results.

### Only Managers of the IT Department can delete documents.
When we created the policies in the last example we only did one claim and role check, but you can have more than one which can give you finer grain of control of enforcing requirements.

Add the following policy after "ManagersOnly":

```c#
options.AddPolicy("ITManagerOnly", policy =>
{
    policy.RequireClaim("Department", "IT");
    policy.RequireRole("Manager");
});
```

Add the following Authorize attribute to the ```DeleteDocument``` method.
```c#
 [Authorize(Policy = "ITManagerOnly")]
 ```
 
 Test results in Postman.

### Members can only view documents for their department or flagged as All.
Claims can also be used to build queries to enforce requirements.

Replace the ```GetPublicDocuments()`` method with:
```c#
[HttpGet]
[Route("")]
public IActionResult GetPublicDocuments()
{
    _logger.LogInformation("Public Documents were accessed.");

    var department = User.FindFirstValue("Department");

    var documents = GetDocuments()
        .Where(
            p =>
                (p.Department == "All" ||
                    p.Department.Equals(department, StringComparison.CurrentCultureIgnoreCase))
                && !p.ManagerOnly);

    return Ok(documents);
}
```
And replace the ```GetManagerDocuments()``` method with:
```c#
[HttpGet]
[Route("managers")]
[Authorize(Policy= "ManagersOnly")]
public IActionResult GetManagerDocuments()
{
    _logger.LogInformation("Manager Documents were accessed.");
    var department = User.FindFirstValue("Department");
    var documents = GetDocuments()
        .Where(
            p =>
                (p.Department == "All" ||
                    p.Department.Equals(department, StringComparison.CurrentCultureIgnoreCase))
                && p.ManagerOnly);

    return Ok(documents);
}
```
### Resource Authorization
The last three requirements:
1. Members can only view documents from their department or flagged as All.
2. Members can create documents for their departments or All.
3. Documents can only be modified by owners or department managers.

These policies are more complex and resource dependent. In these kinds of cases you can't use a configured policy. You'll need to use authorization as a service and have it injected into your controller. That has already been done, but a handler still needs to be created for the service to use.

- Under the "Membership" folder create a new folder nammed "Custom".
- Add a new class named ```DocumentAuthorizationHandler.cs``` and add the following:

```c#
namespace IdentityDemo.Membership.Custom
{
    public class DocumentAuthorizationHandler :
       AuthorizationHandler<OperationAuthorizationRequirement, Document>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
                                                    OperationAuthorizationRequirement requirement,
                                                    Document resource)
        {
            var isManager = context.User.IsInRole("Manager");
            var department = context.User.FindFirstValue("Department");

            switch (requirement.Name)
            {
                case "Read":
                    if (resource.ManagerOnly && !isManager ||
                        resource.Department != department)
                    {
                        context.Fail();
                    }
                    else
                    {
                        context.Succeed(requirement);
                    }
                    break;
                case "Update":

                    if (resource.Owner == context.User.FindFirstValue(ClaimTypes.NameIdentifier))
                    {
                        context.Succeed(requirement);
                    }
                    else if (isManager && resource.Department == department)
                    {
                        context.Succeed(requirement);
                    }
                    else
                    {
                        context.Fail();
                    }
                    break;
            } 
            return Task.CompletedTask;
        }
    }
}
```
Add a class named ```Operations.cs``` and add the following:

```c#
namespace IdentityDemo.Membership.Custom
{
    public static class Operations
    {
        public static OperationAuthorizationRequirement Create =
            new OperationAuthorizationRequirement { Name = "Create" };
        public static OperationAuthorizationRequirement Read =
            new OperationAuthorizationRequirement { Name = "Read" };
        public static OperationAuthorizationRequirement Update =
            new OperationAuthorizationRequirement { Name = "Update" };
        public static OperationAuthorizationRequirement Delete =
            new OperationAuthorizationRequirement { Name = "Delete" };
    }
}
```
This will serve as a helper class for the ```OperationAuthorizationRequirement``` class for passing this requirement as a parameter.

Register the handler in ```ConfigureServices``` method :

```c#
services.AddSingleton<IAuthorizationHandler, DocumentAuthorizationHandler>();
```

Back in the ```DocumentsController``` replace the ```GetDocument(int id)``` method with:
```c#
[HttpGet]
[Route("{id:int}")]
public async Task<IActionResult> GetDocument(int id)
{
    _logger.LogInformation($"Public Document {id} were accessed.");

    var result = GetDocuments().FirstOrDefault(d => d.Id == id);

    if (result == null)
    {
        return NotFound();
    }

    if (!await _authorizationService.AuthorizeAsync(User, result, Operations.Read))
    {
        return StatusCode(StatusCodes.Status403Forbidden);
    }

    return Ok(result);
}
```
Replace the ```CreateDepartmentDocument``` and ```UpdateDeparmentDocument``` methods with:
```c#
[HttpPost]
public IActionResult CreateDepartmentDocument([FromBody] Document model)
{
    if (!ModelState.IsValid)
    {
        return BadRequest(ModelState);
    }

    var department = User.FindFirstValue("Department");
    var isManager = User.IsInRole("Manager");

    model.Id = GetDocuments().Count() + 1;
    model.Owner = User.FindFirstValue(ClaimTypes.NameIdentifier);
    model.Department = department;
    if (model.ManagerOnly && !isManager)
    {
        model.ManagerOnly = false;
    }
    _logger.LogInformation("Document created");

    return Ok(model);
}

[HttpPut]
[Route("{id:int}")]
public async Task<IActionResult> UpdateDeparmentDocument(int id, [FromBody] Document model)
{
    var document = GetDocuments().FirstOrDefault(p => p.Id == id);
    if (document == null)
    {
        return NotFound();
    }

    if (! await _authorizationService.AuthorizeAsync(User, document, Operations.Update))
    {
        return StatusCode(StatusCodes.Status403Forbidden);
    }

    document.Content = model.Content;
    document.Department = model.Department;
    document.ManagerOnly = model.ManagerOnly;
    document.Owner = User.FindFirstValue(ClaimTypes.NameIdentifier);

    _logger.LogInformation("Document Modified");
    return Ok(document);
}
```
Test results in Postman.

