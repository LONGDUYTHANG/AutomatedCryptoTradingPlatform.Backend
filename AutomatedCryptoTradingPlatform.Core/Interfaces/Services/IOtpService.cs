namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

public interface IOtpService
{
    Task<string> GenerateAndSendOtpAsync(string email, string type);
    Task<bool> VerifyOtpAsync(string email, string otpCode, string type);
    Task InvalidateOtpAsync(string email, string type);
}
