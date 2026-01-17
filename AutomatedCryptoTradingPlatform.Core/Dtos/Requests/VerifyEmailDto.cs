using System.ComponentModel.DataAnnotations;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Requests;

public class VerifyEmailDto
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    [StringLength(6, MinimumLength = 6)]
    public string OtpCode { get; set; } = string.Empty;
}
