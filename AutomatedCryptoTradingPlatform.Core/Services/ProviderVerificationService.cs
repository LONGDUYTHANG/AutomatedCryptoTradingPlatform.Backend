using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using Microsoft.Extensions.Logging;
using System.Net.Http.Headers;
using System.Text.Json;

namespace AutomatedCryptoTradingPlatform.Core.Services;

/// <summary>
/// Service for verifying OAuth access tokens from various providers
/// </summary>
public class ProviderVerificationService : IProviderVerificationService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<ProviderVerificationService> _logger;

    public ProviderVerificationService(HttpClient httpClient, ILogger<ProviderVerificationService> logger)
    {
        _httpClient = httpClient;
        _logger = logger;
    }

    /// <summary>
    /// Verifies Facebook access token and retrieves user information
    /// Facebook Graph API: https://graph.facebook.com/me?fields=id,email,name&access_token={token}
    /// </summary>
    public async Task<ProviderUserInfo> VerifyFacebookTokenAsync(string accessToken)
    {
        try
        {
            // Call Facebook Graph API to get user info
            var response = await _httpClient.GetAsync(
                $"https://graph.facebook.com/me?fields=id,email,name,picture&access_token={accessToken}"
            );

            var content = await response.Content.ReadAsStringAsync();
            _logger.LogInformation("Facebook API Response Status: {StatusCode}", response.StatusCode);
            _logger.LogInformation("Facebook API Response Body: {Content}", content);

            if (!response.IsSuccessStatusCode)
            {
                throw new UnauthorizedAccessException($"Invalid Facebook token: {content}");
            }

            var userData = JsonSerializer.Deserialize<JsonElement>(content);

            // Extract user information
            var providerId = userData.GetProperty("id").GetString();
            var email = userData.TryGetProperty("email", out var emailProp) ? emailProp.GetString() : null;
            var name = userData.TryGetProperty("name", out var nameProp) ? nameProp.GetString() : null;
            var pictureUrl = userData.TryGetProperty("picture", out var pictureProp) &&
                           pictureProp.TryGetProperty("data", out var dataProp) &&
                           dataProp.TryGetProperty("url", out var urlProp)
                           ? urlProp.GetString()
                           : null;

            _logger.LogInformation("Facebook User Info - ID: {ProviderId}, Email: {Email}, Name: {Name}", 
                providerId, email ?? "NULL", name ?? "NULL");

            if (string.IsNullOrEmpty(providerId))
            {
                throw new UnauthorizedAccessException("Failed to retrieve user ID from Facebook");
            }

            return new ProviderUserInfo
            {
                ProviderId = providerId,
                Email = email,
                Name = name ?? "Facebook User",
                Provider = "Facebook",
                EmailVerified = !string.IsNullOrEmpty(email), // Facebook only returns email if verified
                PictureUrl = pictureUrl
            };
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "HTTP request failed when verifying Facebook token");
            throw new UnauthorizedAccessException($"Failed to verify Facebook token: {ex.Message}", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error when verifying Facebook token");
            throw;
        }
    }

    /// <summary>
    /// Verifies Microsoft access token and retrieves user information
    /// Microsoft Graph API: https://graph.microsoft.com/v1.0/me
    /// </summary>
    public async Task<ProviderUserInfo> VerifyMicrosoftTokenAsync(string accessToken)
    {
        try
        {
            // Create request with Authorization header
            var request = new HttpRequestMessage(HttpMethod.Get, "https://graph.microsoft.com/v1.0/me");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            var response = await _httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new UnauthorizedAccessException($"Invalid Microsoft token: {errorContent}");
            }

            var content = await response.Content.ReadAsStringAsync();
            var userData = JsonSerializer.Deserialize<JsonElement>(content);

            // Extract user information
            // Microsoft uses 'id' or 'userPrincipalName' as unique identifier
            var providerId = userData.TryGetProperty("id", out var idProp) 
                ? idProp.GetString() 
                : userData.GetProperty("userPrincipalName").GetString();

            var email = userData.TryGetProperty("mail", out var mailProp) 
                ? mailProp.GetString() 
                : userData.TryGetProperty("userPrincipalName", out var upnProp) 
                    ? upnProp.GetString() 
                    : null;

            var name = userData.TryGetProperty("displayName", out var displayNameProp) 
                ? displayNameProp.GetString() 
                : null;

            if (string.IsNullOrEmpty(providerId))
            {
                throw new UnauthorizedAccessException("Failed to retrieve user ID from Microsoft");
            }

            return new ProviderUserInfo
            {
                ProviderId = providerId,
                Email = email,
                Name = name ?? "Microsoft User",
                Provider = "Microsoft",
                EmailVerified = !string.IsNullOrEmpty(email), // Microsoft Graph returns verified emails
                PictureUrl = null // Can be fetched with additional API call if needed
            };
        }
        catch (HttpRequestException ex)
        {
            throw new UnauthorizedAccessException($"Failed to verify Microsoft token: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Verifies GitHub access token and retrieves user information
    /// GitHub API: https://api.github.com/user
    /// </summary>
    public async Task<ProviderUserInfo> VerifyGitHubTokenAsync(string accessToken)
    {
        try
        {
            // Create request with Authorization header
            var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue("AutomatedCryptoTradingPlatform", "1.0"));

            var response = await _httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                var errorContent = await response.Content.ReadAsStringAsync();
                throw new UnauthorizedAccessException($"Invalid GitHub token: {errorContent}");
            }

            var content = await response.Content.ReadAsStringAsync();
            var userData = JsonSerializer.Deserialize<JsonElement>(content);

            // Extract user information
            var providerId = userData.GetProperty("id").GetInt64().ToString();
            var email = userData.TryGetProperty("email", out var emailProp) ? emailProp.GetString() : null;
            var name = userData.TryGetProperty("name", out var nameProp) 
                ? nameProp.GetString() 
                : userData.TryGetProperty("login", out var loginProp) 
                    ? loginProp.GetString() 
                    : null;

            var avatarUrl = userData.TryGetProperty("avatar_url", out var avatarProp) 
                ? avatarProp.GetString() 
                : null;

            if (string.IsNullOrEmpty(providerId))
            {
                throw new UnauthorizedAccessException("Failed to retrieve user ID from GitHub");
            }

            // If email is null, fetch from GitHub emails API
            if (string.IsNullOrEmpty(email))
            {
                email = await GetGitHubPrimaryEmailAsync(accessToken);
            }

            return new ProviderUserInfo
            {
                ProviderId = providerId,
                Email = email,
                Name = name ?? "GitHub User",
                Provider = "GitHub",
                EmailVerified = !string.IsNullOrEmpty(email), // GitHub requires email verification
                PictureUrl = avatarUrl
            };
        }
        catch (HttpRequestException ex)
        {
            throw new UnauthorizedAccessException($"Failed to verify GitHub token: {ex.Message}", ex);
        }
    }

    /// <summary>
    /// Fetches primary email from GitHub user/emails endpoint
    /// GitHub API: https://api.github.com/user/emails
    /// </summary>
    private async Task<string?> GetGitHubPrimaryEmailAsync(string accessToken)
    {
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "https://api.github.com/user/emails");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Headers.UserAgent.Add(new ProductInfoHeaderValue("AutomatedCryptoTradingPlatform", "1.0"));

            var response = await _httpClient.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var content = await response.Content.ReadAsStringAsync();
            var emails = JsonSerializer.Deserialize<JsonElement>(content);

            // Find primary verified email
            foreach (var emailItem in emails.EnumerateArray())
            {
                var isPrimary = emailItem.TryGetProperty("primary", out var primaryProp) && primaryProp.GetBoolean();
                var isVerified = emailItem.TryGetProperty("verified", out var verifiedProp) && verifiedProp.GetBoolean();
                
                if (isPrimary && isVerified && emailItem.TryGetProperty("email", out var emailProp))
                {
                    return emailProp.GetString();
                }
            }

            // Fallback: return first verified email
            foreach (var emailItem in emails.EnumerateArray())
            {
                var isVerified = emailItem.TryGetProperty("verified", out var verifiedProp) && verifiedProp.GetBoolean();
                
                if (isVerified && emailItem.TryGetProperty("email", out var emailProp))
                {
                    return emailProp.GetString();
                }
            }

            return null;
        }
        catch
        {
            return null;
        }
    }
}
