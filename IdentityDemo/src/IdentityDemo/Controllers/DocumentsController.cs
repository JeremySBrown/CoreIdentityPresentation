using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using IdentityDemo.Membership.Custom;
using IdentityDemo.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace IdentityDemo.Controllers
{
    [Route("api/[controller]")]
    [Authorize(Policy = "SalesAndITOnly")]
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

            var department = User.FindFirstValue("Department");

            var documents = GetDocuments()
                .Where(
                    p =>
                        (p.Department == "All" ||
                            p.Department.Equals(department, StringComparison.CurrentCultureIgnoreCase))
                        && !p.ManagerOnly);

            return Ok(documents);
        }

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

        [HttpGet]
        [Route("managers")]
        [Authorize(Policy = "ManagersOnly")]
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

            if (!await _authorizationService.AuthorizeAsync(User, document, Operations.Update))
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

        [HttpDelete]
        [Route("{id:int}")]
        [Authorize(Policy = "ITManagerOnly")]
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