using System.ComponentModel.DataAnnotations;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Requests;

public class Verify2FaDto
{
    [Required(ErrorMessage = "2FA code is required")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "2FA code must be 6 digits")]
    public string Code { get; set; } = string.Empty;
}
