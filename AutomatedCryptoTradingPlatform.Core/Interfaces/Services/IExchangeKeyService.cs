using AutomatedCryptoTradingPlatform.Core.Dtos.Requests;
using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

public interface IExchangeKeyService
{
    Task<ExchangeKeyResponseDto> ConnectExchangeAsync(Guid userId, ConnectExchangeDto connectDto);
    Task DisconnectExchangeAsync(Guid userId, Guid keyId);
    Task<List<ExchangeKeyResponseDto>> GetUserExchangeKeysAsync(Guid userId);
    Task<ExchangeKey?> GetExchangeKeyAsync(Guid userId, Guid keyId);
    Task<VerifyConnectionResponseDto> VerifyConnectionAsync(string exchangeName, string apiKey, string secretKey, string? passphrase = null);
    Task<Dictionary<string, object>> GetAccountInfoAsync(string exchangeName, string apiKey, string secretKey, bool isTestnet = false, string? passphrase = null);
    Task<List<ExchangeDto>> GetSupportedExchangesAsync();
}
