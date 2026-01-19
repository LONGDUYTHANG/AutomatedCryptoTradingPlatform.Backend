namespace AutomatedCryptoTradingPlatform.Core.Dtos.Responses;

public class ExchangeKeyResponseDto
{
    public Guid KeyId { get; set; }
    public string ExchangeName { get; set; } = string.Empty;
    public string ApiKeyMasked { get; set; } = string.Empty; // e.g., "abc***xyz"
    public string? Label { get; set; }
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastVerified { get; set; }
}
