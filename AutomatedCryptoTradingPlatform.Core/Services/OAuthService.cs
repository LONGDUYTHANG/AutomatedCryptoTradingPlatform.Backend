using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using Google.Apis.Auth;
using Microsoft.Extensions.Configuration;

namespace AutomatedCryptoTradingPlatform.Core.Services;

public class OAuthService : IOAuthService
{
    private readonly IConfiguration _configuration;

    public OAuthService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task<ProviderUserInfo> VerifyGoogleTokenAsync(string idToken)
    {
        try
        {
            var googleClientId = _configuration["OAuthSettings:Google:ClientId"] 
                ?? throw new Exception("Google ClientId not configured");

            // Verify the ID token with Google
            var payload = await GoogleJsonWebSignature.ValidateAsync(idToken, new GoogleJsonWebSignature.ValidationSettings
            {
                Audience = new[] { googleClientId }
            });

            if (payload == null)
            {
                throw new Exception("Invalid Google token");
            }

            // Extract user information from the verified payload
            return new ProviderUserInfo
            {
                Provider = "Google",
                ProviderId = payload.Subject, // Google's unique user ID
                Email = payload.Email,
                Name = payload.Name,
                EmailVerified = payload.EmailVerified, // Google verifies email
                PictureUrl = payload.Picture
            };
        }
        catch (InvalidJwtException)
        {
            throw new Exception("Invalid Google token signature");
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to verify Google token: {ex.Message}");
        }
    }
}
