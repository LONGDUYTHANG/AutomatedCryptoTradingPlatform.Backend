using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

public interface ITwoFactorService
{
    /// <summary>
    /// Generate a new 2FA secret and QR code URI for a user
    /// </summary>
    Enable2FaResponseDto GenerateTwoFactorSecret(string email);

    /// <summary>
    /// Verify a TOTP code against a secret
    /// </summary>
    bool VerifyTwoFactorCode(string secret, string code);
}
