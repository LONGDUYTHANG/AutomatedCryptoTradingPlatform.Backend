using System.ComponentModel.DataAnnotations;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Requests;

public class ConnectExchangeDto
{
    [Required(ErrorMessage = "Exchange name is required")]
    public string ExchangeName { get; set; } = string.Empty;

    [Required(ErrorMessage = "API Key is required")]
    public string ApiKey { get; set; } = string.Empty;

    [Required(ErrorMessage = "Secret Key is required")]
    public string SecretKey { get; set; } = string.Empty;

    public string? Label { get; set; }
    public string? Passphrase { get; set; } // For OKX
}
