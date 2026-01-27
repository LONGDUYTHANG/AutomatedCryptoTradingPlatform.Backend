using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AutomatedCryptoTradingPlatform.Core.Dtos.Requests;
using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Helpers;
using AutomatedCryptoTradingPlatform.Core.Interfaces;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using Microsoft.Extensions.Configuration;

namespace AutomatedCryptoTradingPlatform.Core.Services;

public class ExchangeKeyService : IExchangeKeyService
{
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;
    private readonly IExchangeRepository _exchangeRepository;
    private readonly IExchangeAccountRepository _exchangeAccountRepository;
    private readonly IExchangeApiKeyRepository _exchangeApiKeyRepository;

    public ExchangeKeyService(
        IConfiguration configuration, 
        HttpClient httpClient,
        IExchangeRepository exchangeRepository,
        IExchangeAccountRepository exchangeAccountRepository,
        IExchangeApiKeyRepository exchangeApiKeyRepository)
    {
        _configuration = configuration;
        _httpClient = httpClient;
        _exchangeRepository = exchangeRepository;
        _exchangeAccountRepository = exchangeAccountRepository;
        _exchangeApiKeyRepository = exchangeApiKeyRepository;
    }

    public async Task<ExchangeKeyResponseDto> ConnectExchangeAsync(Guid userId, ConnectExchangeDto connectDto)
    {
        // Convert Guid userId to long (assuming User.Id in database)
        long userIdLong = ConvertGuidToLong(userId);
        
        // Validate exchange name and get exchange entity
        var exchange = await _exchangeRepository.GetByNameAsync(connectDto.ExchangeName);
        if (exchange == null)
        {
            throw new Exception($"Unsupported exchange: {connectDto.ExchangeName}");
        }

        // Verify connection first
        var verifyResult = await VerifyConnectionAsync(
            connectDto.ExchangeName, 
            connectDto.ApiKey, 
            connectDto.SecretKey, 
            connectDto.Passphrase
        );

        if (!verifyResult.IsValid)
        {
            throw new Exception($"Invalid API credentials: {verifyResult.Message}");
        }

        // Get encryption key from configuration
        var encryptionKey = _configuration["EncryptionSettings:Key"] 
            ?? throw new Exception("Encryption key not configured");

        // Encrypt sensitive data
        var encryptedApiKey = CryptographyHelper.Encrypt(connectDto.ApiKey, encryptionKey);
        var encryptedSecretKey = CryptographyHelper.Encrypt(connectDto.SecretKey, encryptionKey);
        var encryptedPassphrase = !string.IsNullOrEmpty(connectDto.Passphrase)
            ? CryptographyHelper.Encrypt(connectDto.Passphrase, encryptionKey)
            : null;

        // Check if user already has an account for this exchange
        var existingAccount = await _exchangeAccountRepository.GetByUserAndExchangeAsync(userIdLong, exchange.Id);
        
        long accountId;
        if (existingAccount == null)
        {
            // Create new exchange account
            var newAccount = new ExchangeAccount
            {
                UserId = userIdLong,
                ExchangeId = exchange.Id,
                Label = connectDto.Label ?? $"{connectDto.ExchangeName} Account",
                CreatedAt = DateTime.UtcNow
            };
            accountId = await _exchangeAccountRepository.CreateAsync(newAccount);
        }
        else
        {
            accountId = existingAccount.Id;
        }

        // Create API key
        var apiKey = new ExchangeApiKey
        {
            ExchangeAccountId = accountId,
            Label = connectDto.Label ?? $"{connectDto.ExchangeName} API Key",
            ApiKey = encryptedApiKey,
            ApiSecret = encryptedSecretKey,
            Passphrase = encryptedPassphrase,
            Permissions = "[]", // TODO: Store actual permissions from verifyResult
            Status = "active",
            CreatedAt = DateTime.UtcNow
        };

        var apiKeyId = await _exchangeApiKeyRepository.CreateAsync(apiKey);
        apiKey.Id = apiKeyId;

        return new ExchangeKeyResponseDto
        {
            KeyId = ConvertLongToGuid(apiKeyId), // Convert back to Guid for backward compatibility
            ExchangeName = exchange.Name,
            ApiKeyMasked = MaskApiKey(connectDto.ApiKey),
            Label = apiKey.Label,
            IsActive = apiKey.Status == "active",
            CreatedAt = apiKey.CreatedAt,
            LastVerified = DateTime.UtcNow
        };
    }

    public async Task DisconnectExchangeAsync(Guid userId, Guid keyId)
    {
        long userIdLong = ConvertGuidToLong(userId);
        long keyIdLong = ConvertGuidToLong(keyId);
        
        // Verify ownership before deletion
        var belongsToUser = await _exchangeApiKeyRepository.BelongsToUserAsync(keyIdLong, userIdLong);
        if (!belongsToUser)
        {
            throw new Exception("Exchange key not found or access denied");
        }

        var deleted = await _exchangeApiKeyRepository.DeleteAsync(keyIdLong);
        if (!deleted)
        {
            throw new Exception("Failed to disconnect exchange");
        }
    }

    public async Task<List<ExchangeKeyResponseDto>> GetUserExchangeKeysAsync(Guid userId)
    {
        long userIdLong = ConvertGuidToLong(userId);
        
        // Get all accounts with relations (Exchange + ApiKeys)
        var accounts = await _exchangeAccountRepository.GetByUserIdWithRelationsAsync(userIdLong);
        
        var encryptionKey = _configuration["EncryptionSettings:Key"] 
            ?? throw new Exception("Encryption key not configured");

        var result = new List<ExchangeKeyResponseDto>();
        
        foreach (var account in accounts)
        {
            foreach (var apiKey in account.ApiKeys)
            {
                result.Add(new ExchangeKeyResponseDto
                {
                    KeyId = ConvertLongToGuid(apiKey.Id),
                    ExchangeName = account.Exchange?.Name ?? "Unknown",
                    ApiKeyMasked = MaskApiKey(CryptographyHelper.Decrypt(apiKey.ApiKey, encryptionKey)),
                    Label = apiKey.Label,
                    IsActive = apiKey.Status == "active",
                    CreatedAt = apiKey.CreatedAt,
                    LastVerified = DateTime.UtcNow // TODO: Add last_verified to database schema
                });
            }
        }

        return result;
    }

    public async Task<ExchangeKey?> GetExchangeKeyAsync(Guid userId, Guid keyId)
    {
        long userIdLong = ConvertGuidToLong(userId);
        long keyIdLong = ConvertGuidToLong(keyId);
        
        // Verify ownership
        var belongsToUser = await _exchangeApiKeyRepository.BelongsToUserAsync(keyIdLong, userIdLong);
        if (!belongsToUser)
        {
            return null;
        }

        var apiKey = await _exchangeApiKeyRepository.GetByIdWithRelationsAsync(keyIdLong);
        if (apiKey == null)
        {
            return null;
        }

        // Map to old ExchangeKey format for backward compatibility
        return new ExchangeKey
        {
            KeyId = ConvertLongToGuid(apiKey.Id),
            UserId = userId,
            ExchangeName = apiKey.Account?.Exchange?.Name ?? "Unknown",
            ApiKey = apiKey.ApiKey,
            SecretKey = apiKey.ApiSecret,
            Passphrase = apiKey.Passphrase,
            Label = apiKey.Label,
            IsActive = apiKey.Status == "active",
            CreatedAt = apiKey.CreatedAt,
            LastVerified = DateTime.UtcNow
        };
    }

    public async Task<VerifyConnectionResponseDto> VerifyConnectionAsync(
        string exchangeName, 
        string apiKey, 
        string secretKey, 
        string? passphrase = null)
    {
        try
        {
            return exchangeName.ToLower() switch
            {
                "binance" => await VerifyBinanceConnectionAsync(apiKey, secretKey, false),
                "binancetestnet" => await VerifyBinanceConnectionAsync(apiKey, secretKey, true),
                "okx" => await VerifyOKXConnectionAsync(apiKey, secretKey, passphrase),
                _ => new VerifyConnectionResponseDto
                {
                    IsValid = false,
                    Message = $"Exchange {exchangeName} verification not implemented"
                }
            };
        }
        catch (Exception ex)
        {
            return new VerifyConnectionResponseDto
            {
                IsValid = false,
                Message = $"Connection verification failed: {ex.Message}"
            };
        }
    }

    private async Task<VerifyConnectionResponseDto> VerifyBinanceConnectionAsync(
        string apiKey, 
        string secretKey,
        bool isTestnet)
    {
        try
        {
            var baseUrl = isTestnet 
                ? "https://testnet.binance.vision" 
                : "https://api.binance.com";

            // Get server time to avoid timestamp issues
            var timestamp = await GetBinanceServerTimeAsync(isTestnet);
            var recvWindow = 60000; // 60 seconds window to handle clock sync issues
            var queryString = $"recvWindow={recvWindow}&timestamp={timestamp}";

            // Create signature
            var signature = CreateHmacSignature(queryString, secretKey);
            var url = $"{baseUrl}/api/v3/account?{queryString}&signature={signature}";

            var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.Add("X-MBX-APIKEY", apiKey);

            var response = await _httpClient.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                return new VerifyConnectionResponseDto
                {
                    IsValid = false,
                    Message = $"Binance API error: {content}"
                };
            }

            var accountInfo = JsonSerializer.Deserialize<Dictionary<string, object>>(content);

            return new VerifyConnectionResponseDto
            {
                IsValid = true,
                Message = "Connection verified successfully",
                AccountInfo = accountInfo
            };
        }
        catch (Exception ex)
        {
            return new VerifyConnectionResponseDto
            {
                IsValid = false,
                Message = $"Binance verification error: {ex.Message}"
            };
        }
    }

    private async Task<VerifyConnectionResponseDto> VerifyOKXConnectionAsync(
        string apiKey, 
        string secretKey, 
        string? passphrase)
    {
        try
        {
            if (string.IsNullOrEmpty(passphrase))
            {
                return new VerifyConnectionResponseDto
                {
                    IsValid = false,
                    Message = "Passphrase is required for OKX"
                };
            }

            var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            var method = "GET";
            var requestPath = "/api/v5/account/balance";
            
            // Create signature for OKX
            var prehashString = timestamp + method + requestPath;
            var signature = Convert.ToBase64String(
                new HMACSHA256(Encoding.UTF8.GetBytes(secretKey))
                    .ComputeHash(Encoding.UTF8.GetBytes(prehashString))
            );

            var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.okx.com{requestPath}");
            request.Headers.Add("OK-ACCESS-KEY", apiKey);
            request.Headers.Add("OK-ACCESS-SIGN", signature);
            request.Headers.Add("OK-ACCESS-TIMESTAMP", timestamp);
            request.Headers.Add("OK-ACCESS-PASSPHRASE", passphrase);

            var response = await _httpClient.SendAsync(request);
            var content = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                return new VerifyConnectionResponseDto
                {
                    IsValid = false,
                    Message = $"OKX API error: {content}"
                };
            }

            return new VerifyConnectionResponseDto
            {
                IsValid = true,
                Message = "OKX connection verified successfully"
            };
        }
        catch (Exception ex)
        {
            return new VerifyConnectionResponseDto
            {
                IsValid = false,
                Message = $"OKX verification error: {ex.Message}"
            };
        }
    }

    private static string CreateHmacSignature(string message, string secret)
    {
        var keyBytes = Encoding.UTF8.GetBytes(secret);
        var messageBytes = Encoding.UTF8.GetBytes(message);

        using var hmac = new HMACSHA256(keyBytes);
        var hashBytes = hmac.ComputeHash(messageBytes);
        
        return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
    }

    private static string MaskApiKey(string apiKey)
    {
        if (string.IsNullOrEmpty(apiKey) || apiKey.Length < 10)
            return "***";

        return $"{apiKey.Substring(0, 4)}***{apiKey.Substring(apiKey.Length - 4)}";
    }

    public async Task<Dictionary<string, object>> GetAccountInfoAsync(
        string exchangeName,
        string apiKey,
        string secretKey,
        bool isTestnet = false,
        string? passphrase = null)
    {
        try
        {
            return exchangeName.ToLower() switch
            {
                "binance" => await GetBinanceAccountInfoAsync(apiKey, secretKey, isTestnet),
                "binancetestnet" => await GetBinanceAccountInfoAsync(apiKey, secretKey, true),
                "okx" => await GetOKXAccountInfoAsync(apiKey, secretKey, passphrase),
                _ => throw new Exception($"Exchange {exchangeName} not supported")
            };
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to get account info: {ex.Message}");
        }
    }

    private async Task<long> GetBinanceServerTimeAsync(bool isTestnet)
    {
        var baseUrl = isTestnet
            ? "https://testnet.binance.vision"
            : "https://api.binance.com";

        try
        {
            var response = await _httpClient.GetAsync($"{baseUrl}/api/v3/time");
            var content = await response.Content.ReadAsStringAsync();
            var timeData = JsonSerializer.Deserialize<Dictionary<string, object>>(content);
            
            if (timeData != null && timeData.ContainsKey("serverTime"))
            {
                return Convert.ToInt64(timeData["serverTime"].ToString());
            }
        }
        catch
        {
            // Fallback to local time if server time request fails
        }
        
        return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    }

    private async Task<Dictionary<string, object>> GetBinanceAccountInfoAsync(
        string apiKey,
        string secretKey,
        bool isTestnet)
    {
        var baseUrl = isTestnet
            ? "https://testnet.binance.vision"
            : "https://api.binance.com";

        // Get server time to avoid timestamp issues
        var timestamp = await GetBinanceServerTimeAsync(isTestnet);
        var recvWindow = 60000; // 60 seconds window to handle clock sync issues
        var queryString = $"recvWindow={recvWindow}&timestamp={timestamp}";
        var signature = CreateHmacSignature(queryString, secretKey);
        var url = $"{baseUrl}/api/v3/account?{queryString}&signature={signature}";

        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Add("X-MBX-APIKEY", apiKey);

        var response = await _httpClient.SendAsync(request);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new Exception($"Binance API error: {content}");
        }

        var accountData = JsonSerializer.Deserialize<Dictionary<string, object>>(content)
            ?? throw new Exception("Failed to parse Binance account data");

        // Extract useful info - Binance account includes uid field
        return new Dictionary<string, object>
        {
            ["exchange"] = isTestnet ? "BinanceTestnet" : "Binance",
            ["uid"] = accountData.ContainsKey("uid") ? accountData["uid"] : accountData.GetValueOrDefault("accountId", "unknown"),
            ["canTrade"] = accountData.ContainsKey("canTrade") ? accountData["canTrade"] : false,
            ["canWithdraw"] = accountData.ContainsKey("canWithdraw") ? accountData["canWithdraw"] : false,
            ["canDeposit"] = accountData.ContainsKey("canDeposit") ? accountData["canDeposit"] : false,
            ["accountType"] = accountData.ContainsKey("accountType") ? accountData["accountType"] : "UNKNOWN",
            ["updateTime"] = accountData.ContainsKey("updateTime") ? accountData["updateTime"] : 0
        };
    }

    private async Task<Dictionary<string, object>> GetOKXAccountInfoAsync(
        string apiKey,
        string secretKey,
        string? passphrase)
    {
        if (string.IsNullOrEmpty(passphrase))
        {
            throw new Exception("Passphrase is required for OKX");
        }

        var timestamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        var method = "GET";
        var requestPath = "/api/v5/account/config";

        var prehashString = timestamp + method + requestPath;
        var signature = Convert.ToBase64String(
            new HMACSHA256(Encoding.UTF8.GetBytes(secretKey))
                .ComputeHash(Encoding.UTF8.GetBytes(prehashString))
        );

        var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.okx.com{requestPath}");
        request.Headers.Add("OK-ACCESS-KEY", apiKey);
        request.Headers.Add("OK-ACCESS-SIGN", signature);
        request.Headers.Add("OK-ACCESS-TIMESTAMP", timestamp);
        request.Headers.Add("OK-ACCESS-PASSPHRASE", passphrase);

        var response = await _httpClient.SendAsync(request);
        var content = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new Exception($"OKX API error: {content}");
        }

        var result = JsonSerializer.Deserialize<Dictionary<string, object>>(content)
            ?? throw new Exception("Failed to parse OKX account data");

        // OKX returns: { "code": "0", "msg": "", "data": [{ "uid": "...", "acctLv": "...", ... }] }
        string uid = "unknown";
        if (result.ContainsKey("data") && result["data"] != null)
        {
            var dataElement = result["data"] as JsonElement?;
            if (dataElement.HasValue && dataElement.Value.ValueKind == JsonValueKind.Array)
            {
                var dataArray = dataElement.Value;
                if (dataArray.GetArrayLength() > 0)
                {
                    var firstItem = dataArray[0];
                    if (firstItem.TryGetProperty("uid", out JsonElement uidElement))
                    {
                        uid = uidElement.GetString() ?? "unknown";
                    }
                }
            }
        }

        return new Dictionary<string, object>
        {
            ["exchange"] = "OKX",
            ["uid"] = uid,
            ["data"] = result
        };
    }

    // Helper methods for Guid <-> long conversion (backward compatibility)
    private static long ConvertGuidToLong(Guid guid)
    {
        // Use first 8 bytes of Guid to create long
        var bytes = guid.ToByteArray();
        return BitConverter.ToInt64(bytes, 0);
    }

    private static Guid ConvertLongToGuid(long value)
    {
        // Create Guid from long (pad with zeros)
        var bytes = new byte[16];
        BitConverter.GetBytes(value).CopyTo(bytes, 0);
        return new Guid(bytes);
    }

    public async Task<List<ExchangeDto>> GetSupportedExchangesAsync()
    {
        var exchanges = await _exchangeRepository.GetAllAsync();
        
        return exchanges.Select(e => new ExchangeDto
        {
            Id = e.Id,
            Name = e.Name,
            Type = e.Type
        }).ToList();
    }
}
