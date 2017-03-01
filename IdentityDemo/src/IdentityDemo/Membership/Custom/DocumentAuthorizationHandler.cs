using System.Security.Claims;
using System.Threading.Tasks;
using IdentityDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;

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