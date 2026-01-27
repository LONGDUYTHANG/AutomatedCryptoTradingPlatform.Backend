namespace AutomatedCryptoTradingPlatform.Core.Dtos.Responses;

/// <summary>
/// DTO representing verified user information from OAuth provider
/// </summary>
public class ProviderUserInfo
{
    /// <summary>
    /// Unique identifier from the provider (e.g., Facebook user ID, Microsoft object ID, GitHub user ID)
    /// </summary>
    public required string ProviderId { get; set; }

    /// <summary>
    /// User's email address from the provider
    /// </summary>
    public string? Email { get; set; }

    /// <summary>
    /// User's full name from the provider
    /// </summary>
    public string? Name { get; set; }

    /// <summary>
    /// OAuth provider name (Facebook, Microsoft, GitHub)
    /// </summary>
    public required string Provider { get; set; }

    /// <summary>
    /// Indicates if the email was verified by the provider
    /// </summary>
    public bool EmailVerified { get; set; }

    /// <summary>
    /// User's profile picture URL (optional)
    /// </summary>
    public string? PictureUrl { get; set; }
}
