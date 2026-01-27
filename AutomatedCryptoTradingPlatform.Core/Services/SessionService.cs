using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Repositories;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AutomatedCryptoTradingPlatform.Core.Services;

public class SessionService : ISessionService
{
    private readonly ISessionRepository _sessionRepository;
    private readonly IRedisService _redisService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<SessionService> _logger;
    private readonly string _jwtSecret;
    private readonly string _jwtIssuer;
    private readonly string _jwtAudience;
    private const string REDIS_ACCESS_TOKEN_PREFIX = "access:";
    private const string REDIS_REFRESH_TOKEN_PREFIX = "refresh:";
    private const int ACCESS_TOKEN_TTL_SECONDS = 300; // 5 minutes
    private const int REFRESH_TOKEN_TTL_DAYS = 30; // 30 days

    public SessionService(
        ISessionRepository sessionRepository,
        IRedisService redisService,
        IConfiguration configuration,
        ILogger<SessionService> logger)
    {
        _sessionRepository = sessionRepository;
        _redisService = redisService;
        _configuration = configuration;
        _logger = logger;

        _jwtSecret = configuration["JwtSettings:SecretKey"] ?? throw new Exception("JWT SecretKey not configured");
        _jwtIssuer = configuration["JwtSettings:Issuer"] ?? "AutomatedCryptoTradingPlatform";
        _jwtAudience = configuration["JwtSettings:Audience"] ?? "AutomatedCryptoTradingPlatform";
    }

    public async Task<(long SessionId, string AccessToken, string RefreshToken)> CreateSessionAsync(
        long userId, 
        string ipAddress, 
        string userAgent,
        int sessionDurationDays = 30)
    {
        // Generate refresh token (long-lived token for session renewal)
        var refreshToken = Guid.NewGuid().ToString("N"); // 32-char hex string
        var refreshTokenHash = BCrypt.Net.BCrypt.HashPassword(refreshToken);

        // Create session in database
        var session = new AuthSession
        {
            UserId = userId,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            RefreshTokenHash = refreshTokenHash,
            CreatedAt = DateTime.UtcNow,
            LastActiveAt = DateTime.UtcNow,
            ExpiredAt = DateTime.UtcNow.AddDays(sessionDurationDays)
        };

        var createdSession = await _sessionRepository.CreateAsync(session);

        // Generate access token (short-lived JWT)
        var accessToken = GenerateAccessToken(userId, createdSession.Id);

        // Store access token in Redis with 5-minute TTL
        var accessRedisKey = $"{REDIS_ACCESS_TOKEN_PREFIX}{createdSession.Id}";
        await _redisService.SetStringAsync(accessRedisKey, accessToken, TimeSpan.FromSeconds(ACCESS_TOKEN_TTL_SECONDS));

        // Store refresh token in Redis with 30-day TTL
        var refreshRedisKey = $"{REDIS_REFRESH_TOKEN_PREFIX}{createdSession.Id}";
        await _redisService.SetStringAsync(refreshRedisKey, refreshToken, TimeSpan.FromDays(REFRESH_TOKEN_TTL_DAYS));

        _logger.LogInformation("Created new session {SessionId} for user {UserId} with access and refresh tokens", createdSession.Id, userId);

        return (createdSession.Id, accessToken, refreshToken);
    }

    public async Task<AuthSession?> GetSessionAsync(long sessionId)
    {
        return await _sessionRepository.GetByIdAsync(sessionId);
    }

    public async Task<string?> GetOrRefreshAccessTokenAsync(long sessionId)
    {
        // Try to get from Redis first
        var redisKey = $"{REDIS_ACCESS_TOKEN_PREFIX}{sessionId}";
        var cachedToken = await _redisService.GetStringAsync(redisKey);

        if (!string.IsNullOrEmpty(cachedToken))
        {
            // Update last active
            await _sessionRepository.UpdateLastActiveAsync(sessionId);
            return cachedToken;
        }

        // Not in Redis, validate session from database and regenerate
        var session = await _sessionRepository.GetByIdAsync(sessionId);

        if (session == null || !session.IsActive)
        {
            _logger.LogWarning("Session {SessionId} is invalid or expired", sessionId);
            return null;
        }

        // Regenerate access token
        var newToken = GenerateAccessToken(session.UserId, sessionId);

        // Store in Redis
        await _redisService.SetStringAsync(redisKey, newToken, TimeSpan.FromSeconds(ACCESS_TOKEN_TTL_SECONDS));

        // Update last active
        await _sessionRepository.UpdateLastActiveAsync(sessionId);

        _logger.LogInformation("Regenerated access token for session {SessionId}", sessionId);

        return newToken;
    }

    public async Task<string?> ValidateAndGetAccessTokenAsync(long sessionId)
    {
        return await GetOrRefreshAccessTokenAsync(sessionId);
    }

    public async Task<string?> RefreshAccessTokenAsync(long sessionId, string refreshToken)
    {
        // Validate session from database
        var session = await _sessionRepository.GetByIdAsync(sessionId);
        if (session == null || !session.IsActive)
        {
            _logger.LogWarning("Session {SessionId} is invalid or expired", sessionId);
            return null;
        }

        // Verify refresh token from Redis
        var refreshRedisKey = $"{REDIS_REFRESH_TOKEN_PREFIX}{sessionId}";
        var storedRefreshToken = await _redisService.GetStringAsync(refreshRedisKey);

        if (string.IsNullOrEmpty(storedRefreshToken) || storedRefreshToken != refreshToken)
        {
            _logger.LogWarning("Invalid refresh token for session {SessionId}", sessionId);
            return null;
        }

        // Verify refresh token hash matches database (optional extra security)
        if (!string.IsNullOrEmpty(session.RefreshTokenHash) && 
            !BCrypt.Net.BCrypt.Verify(refreshToken, session.RefreshTokenHash))
        {
            _logger.LogWarning("Refresh token hash mismatch for session {SessionId}", sessionId);
            return null;
        }

        // Generate new access token
        var newAccessToken = GenerateAccessToken(session.UserId, sessionId);

        // Update access token in Redis
        var accessRedisKey = $"{REDIS_ACCESS_TOKEN_PREFIX}{sessionId}";
        await _redisService.SetStringAsync(accessRedisKey, newAccessToken, TimeSpan.FromSeconds(ACCESS_TOKEN_TTL_SECONDS));

        // Update last active
        await _sessionRepository.UpdateLastActiveAsync(sessionId);

        _logger.LogInformation("Refreshed access token for session {SessionId}", sessionId);

        return newAccessToken;
    }

    public async Task<bool> RevokeSessionAsync(long sessionId)
    {
        // Revoke in database
        var revoked = await _sessionRepository.RevokeAsync(sessionId);

        if (revoked)
        {
            // Delete access token from Redis
            var accessRedisKey = $"{REDIS_ACCESS_TOKEN_PREFIX}{sessionId}";
            await _redisService.DeleteKeyAsync(accessRedisKey);

            // Delete refresh token from Redis
            var refreshRedisKey = $"{REDIS_REFRESH_TOKEN_PREFIX}{sessionId}";
            await _redisService.DeleteKeyAsync(refreshRedisKey);

            _logger.LogInformation("Revoked session {SessionId}", sessionId);
        }

        return revoked;
    }

    public async Task<int> RevokeAllUserSessionsAsync(long userId)
    {
        // Get all active sessions
        var sessions = await _sessionRepository.GetActiveSessionsByUserIdAsync(userId);

        // Delete access tokens from Redis
        foreach (var session in sessions)
        {
            var accessRedisKey = $"{REDIS_ACCESS_TOKEN_PREFIX}{session.Id}";
            await _redisService.DeleteKeyAsync(accessRedisKey);

            var refreshRedisKey = $"{REDIS_REFRESH_TOKEN_PREFIX}{session.Id}";
            await _redisService.DeleteKeyAsync(refreshRedisKey);
        }

        // Revoke in database
        var revokedCount = await _sessionRepository.RevokeAllByUserIdAsync(userId);

        _logger.LogInformation("Revoked {Count} sessions for user {UserId}", revokedCount, userId);

        return revokedCount;
    }

    public async Task<IEnumerable<AuthSession>> GetUserActiveSessionsAsync(long userId)
    {
        return await _sessionRepository.GetActiveSessionsByUserIdAsync(userId);
    }

    public async Task<int> CleanupExpiredSessionsAsync()
    {
        var deleted = await _sessionRepository.DeleteExpiredSessionsAsync();
        
        if (deleted > 0)
        {
            _logger.LogInformation("Cleaned up {Count} expired sessions", deleted);
        }

        return deleted;
    }

    private string GenerateAccessToken(long userId, long sessionId)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
            new Claim("session_id", sessionId.ToString()),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString())
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _jwtIssuer,
            audience: _jwtAudience,
            claims: claims,
            expires: DateTime.UtcNow.AddSeconds(ACCESS_TOKEN_TTL_SECONDS),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
