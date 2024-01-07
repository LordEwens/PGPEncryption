using System.ComponentModel.DataAnnotations;

namespace PGPEncryption.Models
{
    public class PGPEncryptionModel
    {
        [DataType(DataType.MultilineText)]
        [Display(Name = "PGP Public Key Block")]
        [Required(ErrorMessage = "PGP Public Key Block is required.")]
        public string? PGPPublicKeyBlockInput { get; set; }

        [DataType(DataType.MultilineText)]
        [Display(Name = "Message to encrypt")]
        [Required(ErrorMessage = "A message is required.")]
        public string? PGPInputToEncrypt { get; set; }

    }
}
