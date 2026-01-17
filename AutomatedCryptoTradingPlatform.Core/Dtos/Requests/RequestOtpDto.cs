using System.ComponentModel.DataAnnotations;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Requests;

public class RequestOtpDto
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string Email { get; set; } = string.Empty;
    
    [Required(ErrorMessage = "OTP type is required")]
    public string Type { get; set; } = string.Empty; // Register, ForgotPassword
}
