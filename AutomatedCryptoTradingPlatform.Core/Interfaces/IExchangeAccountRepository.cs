using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces;

/// <summary>
/// Repository interface for ExchangeAccount entity
/// Handles user's exchange account connections
/// </summary>
public interface IExchangeAccountRepository
{
    /// <summary>
    /// Get exchange account by ID
    /// </summary>
    Task<ExchangeAccount?> GetByIdAsync(long id);
    
    /// <summary>
    /// Get exchange account with all related data (Exchange, ApiKeys)
    /// </summary>
    Task<ExchangeAccount?> GetByIdWithRelationsAsync(long id);
    
    /// <summary>
    /// Get all exchange accounts for a user
    /// </summary>
    Task<List<ExchangeAccount>> GetByUserIdAsync(long userId);
    
    /// <summary>
    /// Get all exchange accounts for a user with relations
    /// </summary>
    Task<List<ExchangeAccount>> GetByUserIdWithRelationsAsync(long userId);
    
    /// <summary>
    /// Get user's specific exchange account
    /// </summary>
    Task<ExchangeAccount?> GetByUserAndExchangeAsync(long userId, long exchangeId);
    
    /// <summary>
    /// Create a new exchange account
    /// </summary>
    Task<long> CreateAsync(ExchangeAccount account);
    
    /// <summary>
    /// Update exchange account
    /// </summary>
    Task<bool> UpdateAsync(ExchangeAccount account);
    
    /// <summary>
    /// Delete exchange account (will cascade delete API keys)
    /// </summary>
    Task<bool> DeleteAsync(long id);
    
    /// <summary>
    /// Check if user has an account on specific exchange
    /// </summary>
    Task<bool> ExistsAsync(long userId, long exchangeId);
}
