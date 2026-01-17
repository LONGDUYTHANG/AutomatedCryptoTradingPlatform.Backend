using System.ComponentModel.DataAnnotations;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Requests;

public class BinanceLoginDto
{
    [Required(ErrorMessage = "API Key is required")]
    public string ApiKey { get; set; } = string.Empty;

    [Required(ErrorMessage = "Secret Key is required")]
    public string SecretKey { get; set; } = string.Empty;

    public bool IsTestnet { get; set; } = false;
}
