namespace AutomatedCryptoTradingPlatform.Core.Entities;

/// <summary>
/// Represents a cryptocurrency exchange platform
/// Maps to: exchanges table
/// </summary>
public class Exchange
{
    /// <summary>
    /// Exchange ID (Primary Key)
    /// DB: id BIGSERIAL PRIMARY KEY
    /// </summary>
    public long Id { get; set; }
    
    /// <summary>
    /// Exchange name (e.g., "Binance", "OKX", "Coinbase")
    /// DB: name VARCHAR(50) UNIQUE NOT NULL
    /// </summary>
    public string Name { get; set; } = string.Empty;
    
    /// <summary>
    /// Exchange type: "CEX" (Centralized) or "DEX" (Decentralized)
    /// DB: type VARCHAR(20) NOT NULL
    /// </summary>
    public string Type { get; set; } = string.Empty;
    
    // Navigation properties
    public List<ExchangeAccount> Accounts { get; set; } = new();
}
