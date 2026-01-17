using AutomatedCryptoTradingPlatform.Core.Attributes;

namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class ExchangeKey
{
    [TrackProperty]
    public Guid KeyId { get; set; }
    
    public Guid UserId { get; set; }
    
    public string ExchangeName { get; set; } = string.Empty; // Binance, OKX, etc.
    
    public string ApiKey { get; set; } = string.Empty; // Encrypted
    
    public string SecretKey { get; set; } = string.Empty; // Encrypted
    
    public string? Passphrase { get; set; } // Encrypted, for OKX
    
    public string Label { get; set; } = string.Empty;
    
    public bool IsActive { get; set; } = true;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? UpdatedAt { get; set; }
    
    public DateTime? LastVerified { get; set; }
}
