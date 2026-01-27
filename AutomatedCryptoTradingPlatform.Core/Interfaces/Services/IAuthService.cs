using AutomatedCryptoTradingPlatform.Core.Dtos.Requests;
using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

public interface IAuthService
{
    Task<AuthResponseDto> RegisterAsync(RegisterDto registerDto);
    Task<AuthResponseDto> LoginAsync(LoginDto loginDto);
    Task<AuthResponseDto> ExternalLoginAsync(ExternalLoginDto externalLoginDto);
    Task<string> GenerateJwtTokenAsync(LegacyUser user, bool isRefresh = false, bool partialFor2FA = false);
    Task<LegacyUser?> GetUserByEmailAsync(string email);
    Task<LegacyUser?> GetUserByProviderAsync(string provider, string providerId);
    Task ResetPasswordAsync(ResetPasswordDto resetPasswordDto);
    Task ChangePasswordAsync(Guid userId, ChangePasswordDto changePasswordDto);
    
    // Email Verification
    Task SendVerificationEmailAsync(string email);
    Task VerifyEmailAsync(string email, string otpCode);
    
    // 2FA Methods
    Task<Enable2FaResponseDto> EnableTwoFactorAsync(Guid userId);
    Task VerifyAndActivateTwoFactorAsync(Guid userId, string code);
    Task DisableTwoFactorAsync(Guid userId, string password);
    Task<bool> Verify2FAAsync(Guid userId, string twoFactorCode);
    Task<LegacyUser?> GetUserByIdAsync(Guid userId);
    
    // Exchange Login Methods
    Task<AuthResponseDto> BinanceLoginAsync(BinanceLoginDto binanceLoginDto);
    Task<AuthResponseDto> OkxLoginAsync(OkxLoginDto okxLoginDto);
}
