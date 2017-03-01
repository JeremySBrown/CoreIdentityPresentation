using System.ComponentModel.DataAnnotations;

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