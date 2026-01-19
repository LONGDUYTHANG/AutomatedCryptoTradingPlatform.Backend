using AutomatedCryptoTradingPlatform.Core.Attributes;

namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class Otp
{
    [TrackProperty]
    public Guid Id { get; set; }
    
    public string Email { get; set; } = string.Empty;
    
    public string OtpCode { get; set; } = string.Empty;
    
    public DateTime ExpiresAt { get; set; }
    
    public string Type { get; set; } = string.Empty; // Register, ForgotPassword
    
    public bool IsUsed { get; set; } = false;
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
