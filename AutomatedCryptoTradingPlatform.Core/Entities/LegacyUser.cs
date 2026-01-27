namespace AutomatedCryptoTradingPlatform.Core.Entities;

/// <summary>
/// Legacy User model for backward compatibility with existing services.
/// This wraps the new normalized User structure and provides the old interface.
/// </summary>
public class LegacyUser
{
    // Old properties mapping
    public Guid UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public string? PasswordHash { get; set; }
    public string FullName { get; set; } = string.Empty;
    public bool TwoFactorEnabled { get; set; } = false;
    public string? TwoFactorSecret { get; set; }
    public string Provider { get; set; } = "Local";
    public string? ProviderId { get; set; }
    public string? WalletAddress { get; set; }
    public bool IsEmailVerified { get; set; } = false;
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }

    /// <summary>
    /// Convert from new User model to LegacyUser
    /// </summary>
    public static LegacyUser FromUser(User user)
    {
        var legacy = new LegacyUser
        {
            UserId = GenerateGuidFromLong(user.Id),
            Email = user.Email,
            PasswordHash = user.PasswordHash,
            FullName = user.Profile?.DisplayName ?? user.Username ?? user.Email.Split('@')[0],
            TwoFactorEnabled = user.TwoFactorAuth?.Enabled ?? false,
            TwoFactorSecret = user.TwoFactorAuth?.Secret,
            Provider = user.SocialAccounts.FirstOrDefault()?.Provider ?? 
                       (user.WalletAccounts.Any() ? "Wallet" : "Local"),
            ProviderId = user.SocialAccounts.FirstOrDefault()?.ProviderUserId,
            WalletAddress = user.WalletAccounts.FirstOrDefault()?.WalletAddress,
            IsEmailVerified = user.Status?.Equals("Active", StringComparison.OrdinalIgnoreCase) ?? false,
            IsActive = user.Status?.Equals("Active", StringComparison.OrdinalIgnoreCase) ?? true,
            CreatedAt = user.CreatedAt,
            UpdatedAt = user.UpdatedAt
        };
        
        return legacy;
    }

    /// <summary>
    /// Convert LegacyUser to new User model with related entities
    /// </summary>
    public (User user, UserProfile? profile, SocialAccount? social, WalletAccount? wallet, TwoFactorAuth? twoFactor) ToUser()
    {
        var user = new User
        {
            Email = Email,
            Username = FullName,
            PasswordHash = PasswordHash,
            Status = IsActive ? "active" : "inactive",
            Role = "user",
            CreatedAt = CreatedAt,
            UpdatedAt = UpdatedAt ?? DateTime.UtcNow
        };

        UserProfile? profile = null;
        if (!string.IsNullOrEmpty(FullName))
        {
            profile = new UserProfile
            {
                DisplayName = FullName
            };
        }

        SocialAccount? social = null;
        if (Provider != "Local" && Provider != "Wallet" && !string.IsNullOrEmpty(ProviderId))
        {
            social = new SocialAccount
            {
                Provider = Provider,
                ProviderUserId = ProviderId,
                CreatedAt = CreatedAt
            };
        }

        WalletAccount? wallet = null;
        if (!string.IsNullOrEmpty(WalletAddress))
        {
            wallet = new WalletAccount
            {
                WalletAddress = WalletAddress,
                Chain = "Ethereum", // Default chain
                CreatedAt = CreatedAt
            };
        }

        TwoFactorAuth? twoFactor = null;
        if (TwoFactorEnabled && !string.IsNullOrEmpty(TwoFactorSecret))
        {
            twoFactor = new TwoFactorAuth
            {
                Secret = TwoFactorSecret,
                Enabled = TwoFactorEnabled
            };
        }

        return (user, profile, social, wallet, twoFactor);
    }

    private static Guid GenerateGuidFromLong(long id)
    {
        var bytes = new byte[16];
        BitConverter.GetBytes(id).CopyTo(bytes, 0);
        return new Guid(bytes);
    }
}
