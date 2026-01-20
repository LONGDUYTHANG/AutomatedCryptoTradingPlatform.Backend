namespace AutomatedCryptoTradingPlatform.Core.Dtos.Responses;

public class VerifyConnectionResponseDto
{
    public bool IsValid { get; set; }
    public string Message { get; set; } = string.Empty;
    public Dictionary<string, object>? AccountInfo { get; set; }
}
