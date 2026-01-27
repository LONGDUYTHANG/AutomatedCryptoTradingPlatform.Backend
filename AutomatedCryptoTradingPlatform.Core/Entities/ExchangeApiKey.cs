using AutomatedCryptoTradingPlatform.Core.Attributes;

namespace AutomatedCryptoTradingPlatform.Core.Entities;

/// <summary>
/// Represents API credentials for accessing an exchange account
/// Maps to: exchange_api_keys table
/// </summary>
public class ExchangeApiKey
{
    /// <summary>
    /// API Key ID (Primary Key)
    /// DB: id BIGSERIAL PRIMARY KEY
    /// </summary>
    [TrackProperty]
    public long Id { get; set; }
    
    /// <summary>
    /// Exchange Account ID (Foreign Key to exchange_accounts table)
    /// DB: exchange_account_id BIGINT NOT NULL REFERENCES exchange_accounts(id) ON DELETE CASCADE
    /// </summary>
    public long ExchangeAccountId { get; set; }
    
    /// <summary>
    /// Label/name for this API key (e.g., "Trading Bot", "Read-only API")
    /// DB: label TEXT NOT NULL
    /// </summary>
    public string Label { get; set; } = string.Empty;
    
    /// <summary>
    /// Encrypted API Key
    /// DB: api_key TEXT NOT NULL
    /// </summary>
    public string ApiKey { get; set; } = string.Empty;
    
    /// <summary>
    /// Encrypted API Secret
    /// DB: api_secret TEXT NOT NULL
    /// </summary>
    public string ApiSecret { get; set; } = string.Empty;
    
    /// <summary>
    /// Encrypted passphrase (optional, required for some exchanges like OKX, Coinbase)
    /// DB: passphrase TEXT
    /// </summary>
    public string? Passphrase { get; set; }
    
    /// <summary>
    /// JSON string of permissions (e.g., ["read", "trade", "withdraw"])
    /// DB: permissions JSONB
    /// </summary>
    public string? Permissions { get; set; }
    
    /// <summary>
    /// API key status: "active", "inactive", "expired", "revoked"
    /// DB: status VARCHAR(20) DEFAULT 'active'
    /// </summary>
    public string Status { get; set; } = "active";
    
    /// <summary>
    /// API key creation timestamp
    /// DB: created_at TIMESTAMPTZ DEFAULT now()
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    /// <summary>
    /// Last time this API key was verified (not in DB, for backward compatibility)
    /// </summary>
    public DateTime? LastVerified { get; set; }
    
    // Navigation properties
    public ExchangeAccount? Account { get; set; }
}
