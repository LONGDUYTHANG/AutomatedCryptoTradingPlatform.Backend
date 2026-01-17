using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AutomatedCryptoTradingPlatform.Core.Dtos.Requests;
using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Helpers;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using Microsoft.Extensions.Configuration;

namespace AutomatedCryptoTradingPlatform.Core.Services;

public class ExchangeKeyService : IExchangeKeyService
{
    // In-memory storage (will be replaced with database)
    private static readonly Dictionary<string, List<ExchangeKey>> _exchangeKeys = new();
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;

    public ExchangeKeyService(IConfiguration configuration, HttpClient httpClient)
    {
        _configuration = configuration;
        _httpClient = httpClient;
    }

    public async Task<ExchangeKeyResponseDto> ConnectExchangeAsync(Guid userId, ConnectExchangeDto connectDto)
    {
        // Validate exchange name
        var validExchanges = new[] { "Binance", "OKX", "BinanceTestnet" };
        if (!validExchanges.Contains(connectDto.ExchangeName, StringComparer.OrdinalIgnoreCase))
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

        // Create exchange key entity
        var exchangeKey = new ExchangeKey
        {
            KeyId = Guid.NewGuid(),
            UserId = userId,
            ExchangeName = connectDto.ExchangeName,
            ApiKey = encryptedApiKey,
            SecretKey = encryptedSecretKey,
            Passphrase = encryptedPassphrase,
            Label = connectDto.Label ?? $"{connectDto.ExchangeName} Account",
            IsActive = true,
            CreatedAt = DateTime.UtcNow,
            LastVerified = DateTime.UtcNow
        };

        // Store in memory
        var userKey = userId.ToString();
        if (!_exchangeKeys.ContainsKey(userKey))
        {
            _exchangeKeys[userKey] = new List<ExchangeKey>();
        }

        _exchangeKeys[userKey].Add(exchangeKey);

        return new ExchangeKeyResponseDto
        {
            KeyId = exchangeKey.KeyId,
            ExchangeName = exchangeKey.ExchangeName,
            ApiKeyMasked = MaskApiKey(connectDto.ApiKey),
            Label = exchangeKey.Label,
            IsActive = exchangeKey.IsActive,
            CreatedAt = exchangeKey.CreatedAt,
            LastVerified = exchangeKey.LastVerified
        };
    }

    public async Task DisconnectExchangeAsync(Guid userId, Guid keyId)
    {
        var userKey = userId.ToString();
        
        if (!_exchangeKeys.ContainsKey(userKey))
        {
            throw new Exception("No exchange keys found for this user");
        }

        var exchangeKey = _exchangeKeys[userKey].FirstOrDefault(k => k.KeyId == keyId);
        if (exchangeKey == null)
        {
            throw new Exception("Exchange key not found");
        }

        _exchangeKeys[userKey].Remove(exchangeKey);
        await Task.CompletedTask;
    }

    public async Task<List<ExchangeKeyResponseDto>> GetUserExchangeKeysAsync(Guid userId)
    {
        var userKey = userId.ToString();
        
        if (!_exchangeKeys.ContainsKey(userKey))
        {
            return new List<ExchangeKeyResponseDto>();
        }

        var encryptionKey = _configuration["EncryptionSettings:Key"] 
            ?? throw new Exception("Encryption key not configured");

        var keys = _exchangeKeys[userKey].Select(k => new ExchangeKeyResponseDto
        {
            KeyId = k.KeyId,
            ExchangeName = k.ExchangeName,
            ApiKeyMasked = MaskApiKey(CryptographyHelper.Decrypt(k.ApiKey, encryptionKey)),
            Label = k.Label,
            IsActive = k.IsActive,
            CreatedAt = k.CreatedAt,
            LastVerified = k.LastVerified
        }).ToList();

        return await Task.FromResult(keys);
    }

    public async Task<ExchangeKey?> GetExchangeKeyAsync(Guid userId, Guid keyId)
    {
        var userKey = userId.ToString();
        
        if (!_exchangeKeys.ContainsKey(userKey))
        {
            return null;
        }

        var exchangeKey = _exchangeKeys[userKey].FirstOrDefault(k => k.KeyId == keyId);
        return await Task.FromResult(exchangeKey);
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
}
