namespace AutomatedCryptoTradingPlatform.Core.Dtos.Responses;

public class AuthResponseDto
{
    public Guid UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public string FullName { get; set; } = string.Empty;
    public bool TwoFactorEnabled { get; set; }
    public bool Require2FA { get; set; } = false;
}
