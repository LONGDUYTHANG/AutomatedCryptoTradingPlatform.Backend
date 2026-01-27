using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces;

/// <summary>
/// Repository interface for ExchangeApiKey entity
/// Handles API keys for exchange accounts
/// </summary>
public interface IExchangeApiKeyRepository
{
    /// <summary>
    /// Get API key by ID
    /// </summary>
    Task<ExchangeApiKey?> GetByIdAsync(long id);
    
    /// <summary>
    /// Get API key with related account and exchange data
    /// </summary>
    Task<ExchangeApiKey?> GetByIdWithRelationsAsync(long id);
    
    /// <summary>
    /// Get all API keys for an exchange account
    /// </summary>
    Task<List<ExchangeApiKey>> GetByAccountIdAsync(long accountId);
    
    /// <summary>
    /// Get all active API keys for an account
    /// </summary>
    Task<List<ExchangeApiKey>> GetActiveByAccountIdAsync(long accountId);
    
    /// <summary>
    /// Get all API keys for a user (across all exchanges)
    /// </summary>
    Task<List<ExchangeApiKey>> GetByUserIdAsync(long userId);
    
    /// <summary>
    /// Get all active API keys for a user
    /// </summary>
    Task<List<ExchangeApiKey>> GetActiveByUserIdAsync(long userId);
    
    /// <summary>
    /// Create a new API key
    /// </summary>
    Task<long> CreateAsync(ExchangeApiKey apiKey);
    
    /// <summary>
    /// Update API key (e.g., change status, update last verified)
    /// </summary>
    Task<bool> UpdateAsync(ExchangeApiKey apiKey);
    
    /// <summary>
    /// Delete API key
    /// </summary>
    Task<bool> DeleteAsync(long id);
    
    /// <summary>
    /// Update API key status
    /// </summary>
    Task<bool> UpdateStatusAsync(long id, string status);
    
    /// <summary>
    /// Update last verified timestamp
    /// </summary>
    Task<bool> UpdateLastVerifiedAsync(long id, DateTime timestamp);
    
    /// <summary>
    /// Check if user owns this API key
    /// </summary>
    Task<bool> BelongsToUserAsync(long apiKeyId, long userId);
}
