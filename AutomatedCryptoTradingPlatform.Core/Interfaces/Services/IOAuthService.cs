using AutomatedCryptoTradingPlatform.Core.Dtos.Requests;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

public interface IOAuthService
{
    Task<ExternalLoginDto> VerifyGoogleTokenAsync(string idToken);
}
