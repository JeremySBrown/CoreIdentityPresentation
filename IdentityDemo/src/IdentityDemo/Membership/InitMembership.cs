using System;
using System.Threading.Tasks;
using IdentityDemo.Membership.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

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