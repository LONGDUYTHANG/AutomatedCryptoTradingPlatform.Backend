using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;
using System.Text.Json;

namespace AutomatedCryptoTradingPlatform.Core.Services;

public class RedisService : IRedisService
{
    private readonly IConnectionMultiplexer _redis;
    private readonly IDatabase _db;
    private readonly ILogger<RedisService> _logger;

    public RedisService(IConnectionMultiplexer redis, ILogger<RedisService> logger)
    {
        _redis = redis;
        _db = redis.GetDatabase();
        _logger = logger;
    }

    public async Task<bool> SetStringAsync(string key, string value, TimeSpan? expiry = null)
    {
        try
        {
            if (expiry.HasValue)
                return await _db.StringSetAsync(key, value, expiry.Value);
            else
                return await _db.StringSetAsync(key, value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting string value for key: {Key}", key);
            return false;
        }
    }

    public async Task<string?> GetStringAsync(string key)
    {
        try
        {
            var value = await _db.StringGetAsync(key);
            return value.HasValue ? value.ToString() : null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting string value for key: {Key}", key);
            return null;
        }
    }

    public async Task<bool> DeleteKeyAsync(string key)
    {
        try
        {
            return await _db.KeyDeleteAsync(key);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error deleting key: {Key}", key);
            return false;
        }
    }

    public async Task<bool> KeyExistsAsync(string key)
    {
        try
        {
            return await _db.KeyExistsAsync(key);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking if key exists: {Key}", key);
            return false;
        }
    }

    public async Task<bool> SetExpiryAsync(string key, TimeSpan expiry)
    {
        try
        {
            return await _db.KeyExpireAsync(key, expiry);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting expiry for key: {Key}", key);
            return false;
        }
    }

    public async Task<TimeSpan?> GetTimeToLiveAsync(string key)
    {
        try
        {
            return await _db.KeyTimeToLiveAsync(key);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting TTL for key: {Key}", key);
            return null;
        }
    }

    public async Task<bool> SetObjectAsync<T>(string key, T value, TimeSpan? expiry = null)
    {
        try
        {
            var json = JsonSerializer.Serialize(value);
            if (expiry.HasValue)
                return await _db.StringSetAsync(key, json, expiry.Value);
            else
                return await _db.StringSetAsync(key, json);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting object for key: {Key}", key);
            return false;
        }
    }

    public async Task<T?> GetObjectAsync<T>(string key)
    {
        try
        {
            var value = await _db.StringGetAsync(key);
            if (!value.HasValue)
                return default;

            return JsonSerializer.Deserialize<T>(value.ToString());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting object for key: {Key}", key);
            return default;
        }
    }

    public async Task<long> IncrementAsync(string key, long value = 1)
    {
        try
        {
            return await _db.StringIncrementAsync(key, value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error incrementing key: {Key}", key);
            return 0;
        }
    }

    public async Task<long> DecrementAsync(string key, long value = 1)
    {
        try
        {
            return await _db.StringDecrementAsync(key, value);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error decrementing key: {Key}", key);
            return 0;
        }
    }
}
