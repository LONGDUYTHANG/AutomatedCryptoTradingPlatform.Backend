using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces;

/// <summary>
/// Repository interface for Exchange entity
/// Handles CRUD operations for exchanges table
/// </summary>
public interface IExchangeRepository
{
    /// <summary>
    /// Get exchange by ID
    /// </summary>
    Task<Exchange?> GetByIdAsync(long id);
    
    /// <summary>
    /// Get exchange by name (e.g., "Binance", "OKX")
    /// </summary>
    Task<Exchange?> GetByNameAsync(string name);
    
    /// <summary>
    /// Get all supported exchanges
    /// </summary>
    Task<List<Exchange>> GetAllAsync();
    
    /// <summary>
    /// Get exchanges by type (CEX or DEX)
    /// </summary>
    Task<List<Exchange>> GetByTypeAsync(string type);
    
    /// <summary>
    /// Create a new exchange
    /// </summary>
    Task<long> CreateAsync(Exchange exchange);
    
    /// <summary>
    /// Update exchange information
    /// </summary>
    Task<bool> UpdateAsync(Exchange exchange);
    
    /// <summary>
    /// Delete exchange
    /// </summary>
    Task<bool> DeleteAsync(long id);
}
