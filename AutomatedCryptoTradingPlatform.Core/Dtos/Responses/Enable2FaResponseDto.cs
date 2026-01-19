namespace AutomatedCryptoTradingPlatform.Core.Dtos.Responses;

public class Enable2FaResponseDto
{
    public string Secret { get; set; } = string.Empty;
    public string QrCodeUri { get; set; } = string.Empty;
    public string ManualEntryKey { get; set; } = string.Empty;
}
