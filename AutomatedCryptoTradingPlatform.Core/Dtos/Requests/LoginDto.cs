using System.ComponentModel.DataAnnotations;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Requests;

public class LoginDto
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = string.Empty;

    // Optional: Only required if user has 2FA enabled
    [StringLength(6, MinimumLength = 6, ErrorMessage = "2FA code must be 6 digits")]
    public string? TwoFactorCode { get; set; }
}
