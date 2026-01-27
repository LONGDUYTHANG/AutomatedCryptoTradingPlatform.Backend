namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class UserProfile
{
    public long UserId { get; set; }
    public string? DisplayName { get; set; }
    public string? AvatarUrl { get; set; }
    public string? Country { get; set; }
    public string? Timezone { get; set; }
}
