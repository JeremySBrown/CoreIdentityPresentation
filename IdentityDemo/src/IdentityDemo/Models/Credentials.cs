using System.ComponentModel.DataAnnotations;

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