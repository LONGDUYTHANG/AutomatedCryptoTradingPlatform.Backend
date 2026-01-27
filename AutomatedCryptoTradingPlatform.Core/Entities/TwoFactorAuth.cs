namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class TwoFactorAuth
{
    public long UserId { get; set; }
    public string Secret { get; set; } = string.Empty;
    public bool Enabled { get; set; }
}
