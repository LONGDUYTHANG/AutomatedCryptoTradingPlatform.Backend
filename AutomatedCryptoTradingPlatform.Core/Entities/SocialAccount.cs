namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class SocialAccount
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public string Provider { get; set; } = string.Empty; // Google, Facebook, Microsoft, GitHub
    public string ProviderUserId { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
}
