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

8 Open the appsettings.json file and add the following after the Logging section.
```javascript
  "Data": {
    "ConnectionString": "Data Source=(localdb)\\MSSQLLocalDB;Initial Catalog=IdentityDemo;Integrated Security=True;Connect Timeout=30;Encrypt=False;TrustServerCertificate=True;ApplicationIntent=ReadWrite;MultiSubnetFailover=False"
  }
```
