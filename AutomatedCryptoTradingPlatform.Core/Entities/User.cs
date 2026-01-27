namespace AutomatedCryptoTradingPlatform.Core.Entities;

/// <summary>
/// Core user entity - maps to users table
/// </summary>
public class User
{
    public long Id { get; set; }
    
    public string Email { get; set; } = string.Empty;
    
    public string? Username { get; set; }
    
    public string? PasswordHash { get; set; }
    
    public string Status { get; set; } = "active"; // active, inactive, banned
    
    public string Role { get; set; } = "user"; // user, admin
    
    public DateTime CreatedAt { get; set; }
    
    public DateTime UpdatedAt { get; set; }
    
    // Navigation properties (not in database)
    public UserProfile? Profile { get; set; }
    public List<SocialAccount> SocialAccounts { get; set; } = new();
    public List<WalletAccount> WalletAccounts { get; set; } = new();
    public TwoFactorAuth? TwoFactorAuth { get; set; }
}
