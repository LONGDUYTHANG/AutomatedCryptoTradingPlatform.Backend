using System.ComponentModel.DataAnnotations;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Requests;

public class GoogleLoginDto
{
    [Required(ErrorMessage = "ID Token is required")]
    public string IdToken { get; set; } = string.Empty;
}
