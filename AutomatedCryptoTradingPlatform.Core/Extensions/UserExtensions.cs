using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Extensions;

/// <summary>
/// Extension methods for User entity to maintain backward compatibility
/// and provide convenient access to related data
/// </summary>
public static class UserExtensions
{
    /// <summary>
    /// Get user ID as Guid (for backward compatibility with old code using UserId as Guid)
    /// </summary>
    public static Guid GetGuidId(this User user)
    {
        // Generate deterministic Guid from long ID
        var bytes = new byte[16];
        BitConverter.GetBytes(user.Id).CopyTo(bytes, 0);
        return new Guid(bytes);
    }
    
    /// <summary>
    /// Get full name from profile or username
    /// </summary>
    public static string GetFullName(this User user)
    {
        return user.Profile?.DisplayName ?? user.Username ?? user.Email.Split('@')[0];
    }
    
    /// <summary>
    /// Check if user has 2FA enabled
    /// </summary>
    public static bool IsTwoFactorEnabled(this User user)
    {
        return user.TwoFactorAuth?.Enabled ?? false;
    }
    
    /// <summary>
    /// Get 2FA secret
    /// </summary>
    public static string? GetTwoFactorSecret(this User user)
    {
        return user.TwoFactorAuth?.Secret;
    }
    
    /// <summary>
    /// Check if user is active
    /// </summary>
    public static bool IsUserActive(this User user)
    {
        return user.Status == "active";
    }
    
    /// <summary>
    /// Get primary provider (first social account or "Local" if none)
    /// </summary>
    public static string GetPrimaryProvider(this User user)
    {
        return user.SocialAccounts.FirstOrDefault()?.Provider ?? "Local";
    }
    
    /// <summary>
    /// Get provider ID from primary social account
    /// </summary>
    public static string? GetProviderId(this User user)
    {
        return user.SocialAccounts.FirstOrDefault()?.ProviderUserId;
    }
    
    /// <summary>
    /// Get primary wallet address
    /// </summary>
    public static string? GetWalletAddress(this User user)
    {
        return user.WalletAccounts.FirstOrDefault()?.WalletAddress;
    }
    
    /// <summary>
    /// Check if email is verified (for now, check if user has social account or is active)
    /// </summary>
    public static bool IsEmailVerifiedFlag(this User user)
    {
        // User is considered verified if:
        // - Has social accounts (verified through OAuth)
        // - Or has wallet accounts (verified through signature)
        // - Or is active and not using "Local" provider
        return user.SocialAccounts.Any() || 
               user.WalletAccounts.Any() || 
               (user.Status == "active" && !string.IsNullOrEmpty(user.PasswordHash));
    }
}
