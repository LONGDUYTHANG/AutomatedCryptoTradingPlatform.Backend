using System.ComponentModel.DataAnnotations;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Requests;

public class OkxLoginDto
{
    [Required(ErrorMessage = "API Key is required")]
    public string ApiKey { get; set; } = string.Empty;

    [Required(ErrorMessage = "Secret Key is required")]
    public string SecretKey { get; set; } = string.Empty;

    [Required(ErrorMessage = "Passphrase is required for OKX")]
    public string Passphrase { get; set; } = string.Empty;
}
