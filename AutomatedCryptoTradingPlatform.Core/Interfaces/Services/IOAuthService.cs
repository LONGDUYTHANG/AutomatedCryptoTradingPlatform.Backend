using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

public interface IOAuthService
{
    Task<ProviderUserInfo> VerifyGoogleTokenAsync(string idToken);
}
