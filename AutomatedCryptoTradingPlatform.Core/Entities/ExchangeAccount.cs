namespace AutomatedCryptoTradingPlatform.Core.Entities;

/// <summary>
/// Represents a user's account on a specific exchange
/// Maps to: exchange_accounts table
/// </summary>
public class ExchangeAccount
{
    /// <summary>
    /// Account ID (Primary Key)
    /// DB: id BIGSERIAL PRIMARY KEY
    /// </summary>
    public long Id { get; set; }
    
    /// <summary>
    /// User ID (Foreign Key to users table)
    /// DB: user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE
    /// </summary>
    public long UserId { get; set; }
    
    /// <summary>
    /// Exchange ID (Foreign Key to exchanges table)
    /// DB: exchange_id BIGINT NOT NULL REFERENCES exchanges(id)
    /// </summary>
    public long ExchangeId { get; set; }
    
    /// <summary>
    /// User-defined label for this account (e.g., "Main Trading Account")
    /// DB: label VARCHAR(100)
    /// </summary>
    public string? Label { get; set; }
    
    /// <summary>
    /// Account creation timestamp
    /// DB: created_at TIMESTAMPTZ DEFAULT now()
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    // Navigation properties
    public User? User { get; set; }
    public Exchange? Exchange { get; set; }
    public List<ExchangeApiKey> ApiKeys { get; set; } = new();
}
