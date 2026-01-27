using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

namespace AutomatedCryptoTradingPlatform.Core.Services;

public class OtpService : IOtpService
{
    private readonly IEmailService _emailService;
    private readonly IRedisService _redisService;
    private const string OTP_PREFIX = "otp:";

    public OtpService(IEmailService emailService, IRedisService redisService)
    {
        _emailService = emailService;
        _redisService = redisService;
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

        // Store in Redis with 5 minutes TTL (key format: otp:email_type)
        var key = $"{OTP_PREFIX}{email.ToLower()}_{type}";
        await _redisService.SetObjectAsync(key, otp, TimeSpan.FromMinutes(5));

        // Send email
        await _emailService.SendOtpEmailAsync(email, otpCode, type);

        return otpCode;
    }

    public async Task<bool> VerifyOtpAsync(string email, string otpCode, string type)
    {
        var key = $"{OTP_PREFIX}{email.ToLower()}_{type}";

        // Get OTP from Redis
        var otp = await _redisService.GetObjectAsync<Otp>(key);
        
        // Check if OTP exists
        if (otp == null)
        {
            return false;
        }

        // Check if already used
        if (otp.IsUsed)
        {
            return false;
        }

        // Check if expired (Redis TTL handles this, but double-check)
        if (DateTime.UtcNow > otp.ExpiresAt)
        {
            await _redisService.DeleteKeyAsync(key);
            return false;
        }

        // Verify OTP code
        if (otp.OtpCode != otpCode)
        {
            return false;
        }

        // Mark as used and update in Redis
        otp.IsUsed = true;
        var remainingTtl = await _redisService.GetTimeToLiveAsync(key);
        await _redisService.SetObjectAsync(key, otp, remainingTtl);

        return true;
    }

    public async Task InvalidateOtpAsync(string email, string type)
    {
        var key = $"{OTP_PREFIX}{email.ToLower()}_{type}";
        await _redisService.DeleteKeyAsync(key);
    }
}
