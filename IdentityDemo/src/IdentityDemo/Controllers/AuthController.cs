using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using IdentityDemo.Membership.Models;
using IdentityDemo.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

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
                            claims.Add(new Claim("Department", user.Department));
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
    }
}