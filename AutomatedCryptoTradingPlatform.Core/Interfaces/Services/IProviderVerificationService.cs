using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

/// <summary>
/// Service for verifying OAuth access tokens and retrieving user information from providers
/// </summary>
public interface IProviderVerificationService
{
    /// <summary>
    /// Verifies a Facebook access token and retrieves user information
    /// </summary>
    /// <param name="accessToken">Facebook access token from client</param>
    /// <returns>Verified user information from Facebook</returns>
    /// <exception cref="UnauthorizedAccessException">If token is invalid</exception>
    Task<ProviderUserInfo> VerifyFacebookTokenAsync(string accessToken);

    /// <summary>
    /// Verifies a Microsoft access token and retrieves user information
    /// </summary>
    /// <param name="accessToken">Microsoft access token from client</param>
    /// <returns>Verified user information from Microsoft Graph API</returns>
    /// <exception cref="UnauthorizedAccessException">If token is invalid</exception>
    Task<ProviderUserInfo> VerifyMicrosoftTokenAsync(string accessToken);

    /// <summary>
    /// Verifies a GitHub access token and retrieves user information
    /// </summary>
    /// <param name="accessToken">GitHub access token from client</param>
    /// <returns>Verified user information from GitHub API</returns>
    /// <exception cref="UnauthorizedAccessException">If token is invalid</exception>
    Task<ProviderUserInfo> VerifyGitHubTokenAsync(string accessToken);
}
