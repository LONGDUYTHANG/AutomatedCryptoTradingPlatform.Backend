using AutomatedCryptoTradingPlatform.Core.Attributes;

namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class User
{
    [TrackProperty]
    public Guid UserId { get; set; }
    
    public string Email { get; set; } = string.Empty;
    
    public string PasswordHash { get; set; } = string.Empty;
    
    public string FullName { get; set; } = string.Empty;
    
    public bool TwoFactorEnabled { get; set; } = false;
    
    public string? TwoFactorSecret { get; set; }
    
    public string Provider { get; set; } = "Local"; // Local, Google, Binance, OKX
    
    public string? ProviderId { get; set; }
    
    public bool IsEmailVerified { get; set; } = false; // Email verification status
    
    public bool IsActive { get; set; } = true;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime? UpdatedAt { get; set; }
}
