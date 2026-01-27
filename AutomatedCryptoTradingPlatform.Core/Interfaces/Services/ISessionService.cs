using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

/// <summary>
/// Session management service
/// Handles session lifecycle: create, validate, refresh, revoke
/// </summary>
public interface ISessionService
{
    /// <summary>
    /// Create new session and store access/refresh tokens in Redis
    /// Returns session_id to be set in HttpOnly cookie
    /// </summary>
    Task<(long SessionId, string AccessToken, string RefreshToken)> CreateSessionAsync(
        long userId, 
        string ipAddress, 
        string userAgent,
        int sessionDurationDays = 30
    );

    /// <summary>
    /// Get active session by ID
    /// </summary>
    Task<AuthSession?> GetSessionAsync(long sessionId);

    /// <summary>
    /// Get access token from Redis (or regenerate if expired)
    /// Updates last_active_at in database
    /// </summary>
    Task<string?> GetOrRefreshAccessTokenAsync(long sessionId);

    /// <summary>
    /// Validate session and return access token
    /// Returns null if session is invalid/expired/revoked
    /// </summary>
    Task<string?> ValidateAndGetAccessTokenAsync(long sessionId);

    /// <summary>
    /// Refresh access token using refresh token
    /// Validates refresh token from Redis and session from DB
    /// Returns new access token if valid
    /// </summary>
    Task<string?> RefreshAccessTokenAsync(long sessionId, string refreshToken);

    /// <summary>
    /// Revoke session (logout)
    /// Deletes access token from Redis
    /// </summary>
    Task<bool> RevokeSessionAsync(long sessionId);

    /// <summary>
    /// Revoke all sessions for a user (security action)
    /// </summary>
    Task<int> RevokeAllUserSessionsAsync(long userId);

    /// <summary>
    /// Get all active sessions for a user
    /// </summary>
    Task<IEnumerable<AuthSession>> GetUserActiveSessionsAsync(long userId);

    /// <summary>
    /// Cleanup expired sessions (background job)
    /// </summary>
    Task<int> CleanupExpiredSessionsAsync();
}
