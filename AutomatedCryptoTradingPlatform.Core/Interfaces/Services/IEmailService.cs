namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

public interface IEmailService
{
    Task SendEmailAsync(string toEmail, string subject, string htmlBody);
    Task SendOtpEmailAsync(string toEmail, string otpCode, string purpose);
}
