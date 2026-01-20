using OtpNet;
using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

namespace AutomatedCryptoTradingPlatform.Core.Services;

public class TwoFactorService : ITwoFactorService
{
    private const string Issuer = "Automated Crypto Trading";

    public Enable2FaResponseDto GenerateTwoFactorSecret(string email)
    {
        // Generate a random 20-byte secret key
        var key = KeyGeneration.GenerateRandomKey(20);
        var base32Secret = Base32Encoding.ToString(key);

        // Create OTP URI for QR code (compatible with Google Authenticator, Authy, etc.)
        var otpUri = $"otpauth://totp/{Uri.EscapeDataString(Issuer)}:{Uri.EscapeDataString(email)}?secret={base32Secret}&issuer={Uri.EscapeDataString(Issuer)}";

        return new Enable2FaResponseDto
        {
            Secret = base32Secret,
            QrCodeUri = otpUri,
            ManualEntryKey = FormatSecretForManualEntry(base32Secret)
        };
    }

    public bool VerifyTwoFactorCode(string secret, string code)
    {
        if (string.IsNullOrWhiteSpace(secret) || string.IsNullOrWhiteSpace(code))
            return false;

        try
        {
            var secretBytes = Base32Encoding.ToBytes(secret);
            var totp = new Totp(secretBytes);

            // Verify with a time window of 1 step (30 seconds before and after)
            return totp.VerifyTotp(code, out _, new VerificationWindow(1, 1));
        }
        catch
        {
            return false;
        }
    }

    private static string FormatSecretForManualEntry(string secret)
    {
        // Format as groups of 4 characters for easier manual entry
        // Example: JBSW Y3DP EBSG K43U MVZX G2LU
        var formatted = string.Empty;
        for (int i = 0; i < secret.Length; i += 4)
        {
            if (i > 0) formatted += " ";
            formatted += secret.Substring(i, Math.Min(4, secret.Length - i));
        }
        return formatted;
    }
}
