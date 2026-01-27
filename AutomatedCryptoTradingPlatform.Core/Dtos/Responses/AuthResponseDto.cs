namespace AutomatedCryptoTradingPlatform.Core.Dtos.Responses;

public class AuthResponseDto
{
    public Guid UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public bool IsEmailVerified { get; set; }
    public bool TwoFactorEnabled { get; set; }
    public bool Require2FA { get; set; } = false;
    public string? Token { get; set; } // JWT token (partial if Require2FA=true, full if Require2FA=false)
}
