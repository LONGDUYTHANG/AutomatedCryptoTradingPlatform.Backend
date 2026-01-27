namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class WalletAccount
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public string WalletAddress { get; set; } = string.Empty;
    public string? Chain { get; set; } // Ethereum, Polygon, BSC, Solana
    public DateTime CreatedAt { get; set; }
}
