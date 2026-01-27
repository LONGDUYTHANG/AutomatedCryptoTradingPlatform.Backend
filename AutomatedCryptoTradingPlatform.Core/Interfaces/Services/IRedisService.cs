namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

/// <summary>
/// Redis service interface for caching and temporary data storage
/// </summary>
public interface IRedisService
{
    /// <summary>
    /// Set a string value in Redis with optional expiration
    /// </summary>
    Task<bool> SetStringAsync(string key, string value, TimeSpan? expiry = null);

    /// <summary>
    /// Get a string value from Redis
    /// </summary>
    Task<string?> GetStringAsync(string key);

    /// <summary>
    /// Delete a key from Redis
    /// </summary>
    Task<bool> DeleteKeyAsync(string key);

    /// <summary>
    /// Check if a key exists in Redis
    /// </summary>
    Task<bool> KeyExistsAsync(string key);

    /// <summary>
    /// Set expiration time for a key
    /// </summary>
    Task<bool> SetExpiryAsync(string key, TimeSpan expiry);

    /// <summary>
    /// Get remaining time to live for a key
    /// </summary>
    Task<TimeSpan?> GetTimeToLiveAsync(string key);

    /// <summary>
    /// Set a complex object in Redis (serialized as JSON)
    /// </summary>
    Task<bool> SetObjectAsync<T>(string key, T value, TimeSpan? expiry = null);

    /// <summary>
    /// Get a complex object from Redis (deserialized from JSON)
    /// </summary>
    Task<T?> GetObjectAsync<T>(string key);

    /// <summary>
    /// Increment a counter
    /// </summary>
    Task<long> IncrementAsync(string key, long value = 1);

    /// <summary>
    /// Decrement a counter
    /// </summary>
    Task<long> DecrementAsync(string key, long value = 1);
}
