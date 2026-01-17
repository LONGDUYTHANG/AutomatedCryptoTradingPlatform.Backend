using System.ComponentModel.DataAnnotations;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Requests;

public class ExternalLoginDto
{
    [Required(ErrorMessage = "Provider is required")]
    public string Provider { get; set; } = string.Empty; // Google, Binance, OKX
    
    [Required(ErrorMessage = "Access token is required")]
    public string AccessToken { get; set; } = string.Empty;
    
    public string? Email { get; set; }
    
    public string? FullName { get; set; }
    
    public string? ProviderId { get; set; }
}
