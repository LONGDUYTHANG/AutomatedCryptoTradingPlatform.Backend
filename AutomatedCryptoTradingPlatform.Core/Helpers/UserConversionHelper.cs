using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Helpers;

/// <summary>
/// Helper methods để convert giữa LegacyUser và normalized database entities
/// </summary>
public static class UserConversionHelper
{
    /// <summary>
    /// Create User entities from LegacyUser (for database insertion)
    /// </summary>
    public static async Task<(User user, UserProfile? profile, SocialAccount? social, WalletAccount? wallet, TwoFactorAuth? twoFactor)> 
        CreateDatabaseEntitiesAsync(LegacyUser legacy)
    {
        var user = new User
        {
            Email = legacy.Email,
            Username = legacy.FullName,
            PasswordHash = legacy.PasswordHash,
            Status = legacy.IsActive ? "active" : "inactive",
            Role = "user",
            CreatedAt = legacy.CreatedAt,
            UpdatedAt = legacy.UpdatedAt ?? DateTime.UtcNow
        };

        UserProfile? profile = null;
        if (!string.IsNullOrEmpty(legacy.FullName))
        {
            profile = new UserProfile
            {
                DisplayName = legacy.FullName
            };
        }

        SocialAccount? social = null;
        if (legacy.Provider != "Local" && legacy.Provider != "Wallet" && !string.IsNullOrEmpty(legacy.ProviderId))
        {
            social = new SocialAccount
            {
                Provider = legacy.Provider,
                ProviderUserId = legacy.ProviderId,
                CreatedAt = legacy.CreatedAt
            };
        }

        WalletAccount? wallet = null;
        if (!string.IsNullOrEmpty(legacy.WalletAddress))
        {
            wallet = new WalletAccount
            {
                WalletAddress = legacy.WalletAddress,
                Chain = "Ethereum",
                CreatedAt = legacy.CreatedAt
            };
        }

        TwoFactorAuth? twoFactor = null;
        if (legacy.TwoFactorEnabled && !string.IsNullOrEmpty(legacy.TwoFactorSecret))
        {
            twoFactor = new TwoFactorAuth
            {
                Secret = legacy.TwoFactorSecret,
                Enabled = legacy.TwoFactorEnabled
            };
        }

        return await Task.FromResult((user, profile, social, wallet, twoFactor));
    }

    /// <summary>
    /// Convert User with relations to LegacyUser
    /// </summary>
    public static LegacyUser ToLegacyUser(User user)
    {
        return LegacyUser.FromUser(user);
    }

    /// <summary>
    /// Generate GUID from long ID for backward compatibility
    /// </summary>
    public static Guid GenerateGuidFromLong(long id)
    {
        var bytes = new byte[16];
        BitConverter.GetBytes(id).CopyTo(bytes, 0);
        return new Guid(bytes);
    }
}
