using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

namespace AutomatedCryptoTradingPlatform.Core.Services;

public class OtpService : IOtpService
{
    // In-memory storage for OTPs (will be replaced with database later)
    private static readonly Dictionary<string, Otp> _otps = new();
    private readonly IEmailService _emailService;

    public OtpService(IEmailService emailService)
    {
        _emailService = emailService;
    }

    public async Task<string> GenerateAndSendOtpAsync(string email, string type)
    {
        // Generate 6-digit OTP
        var random = new Random();
        var otpCode = random.Next(100000, 999999).ToString();

        // Create OTP entity
        var otp = new Otp
        {
            Id = Guid.NewGuid(),
            Email = email.ToLower(),
            OtpCode = otpCode,
            Type = type,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5), // 5 minutes expiry
            IsUsed = false,
            CreatedAt = DateTime.UtcNow
        };

        // Store in memory (key format: email_type)
        var key = $"{email.ToLower()}_{type}";
        _otps[key] = otp;

        // Send email
        await _emailService.SendOtpEmailAsync(email, otpCode, type);

        return otpCode;
    }

    public async Task<bool> VerifyOtpAsync(string email, string otpCode, string type)
    {
        var key = $"{email.ToLower()}_{type}";

        // Check if OTP exists
        if (!_otps.TryGetValue(key, out var otp))
        {
            return false;
        }

        // Check if already used
        if (otp.IsUsed)
        {
            return false;
        }

        // Check if expired
        if (DateTime.UtcNow > otp.ExpiresAt)
        {
            return false;
        }

        // Verify OTP code
        if (otp.OtpCode != otpCode)
        {
            return false;
        }

        // Mark as used
        otp.IsUsed = true;
        _otps[key] = otp;

        return await Task.FromResult(true);
    }

    public async Task InvalidateOtpAsync(string email, string type)
    {
        var key = $"{email.ToLower()}_{type}";
        
        if (_otps.ContainsKey(key))
        {
            _otps.Remove(key);
        }

        await Task.CompletedTask;
    }
}
