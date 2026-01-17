using System.ComponentModel.DataAnnotations;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Requests;

public class Disable2FaDto
{
    [Required(ErrorMessage = "Password is required to disable 2FA")]
    public string Password { get; set; } = string.Empty;
}
