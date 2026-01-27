using System.ComponentModel.DataAnnotations;

namespace AutomatedCryptoTradingPlatform.Core.Dtos.Requests;

/// <summary>
/// DTO for external OAuth login requests
/// User information will be fetched from provider after access token verification
/// </summary>
public class ExternalLoginDto
{
    /// <summary>
    /// OAuth provider name (Facebook, Microsoft, GitHub)
    /// </summary>
    [Required(ErrorMessage = "Provider is required")]
    public string Provider { get; set; } = string.Empty;
    
    /// <summary>
    /// Access token obtained from OAuth provider
    /// Backend will verify this token with the provider and retrieve user information
    /// </summary>
    [Required(ErrorMessage = "Access token is required")]
    public string AccessToken { get; set; } = string.Empty;
    
    /// <summary>
    /// Optional ID token for providers that support it (e.g., Google OIDC)
    /// </summary>
    public string? IdToken { get; set; }
    
    /// <summary>
    /// User's email from OAuth provider
    /// </summary>
    public string? Email { get; set; }
    
    /// <summary>
    /// User's full name from OAuth provider
    /// </summary>
    public string? FullName { get; set; }
    
    /// <summary>
    /// User's ID from OAuth provider
    /// </summary>
    public string? ProviderId { get; set; }
}
