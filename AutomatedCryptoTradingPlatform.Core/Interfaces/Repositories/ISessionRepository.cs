using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Repositories;

/// <summary>
/// Repository for managing auth sessions in PostgreSQL
/// </summary>
public interface ISessionRepository
{
    /// <summary>
    /// Create new session
    /// </summary>
    Task<AuthSession> CreateAsync(AuthSession session);

    /// <summary>
    /// Get session by ID
    /// </summary>
    Task<AuthSession?> GetByIdAsync(long sessionId);

    /// <summary>
    /// Get all active sessions for a user
    /// </summary>
    Task<IEnumerable<AuthSession>> GetActiveSessionsByUserIdAsync(long userId);

    /// <summary>
    /// Update last active timestamp
    /// </summary>
    Task<bool> UpdateLastActiveAsync(long sessionId);

    /// <summary>
    /// Revoke session (logout)
    /// </summary>
    Task<bool> RevokeAsync(long sessionId);

    /// <summary>
    /// Revoke all sessions for a user
    /// </summary>
    Task<int> RevokeAllByUserIdAsync(long userId);

    /// <summary>
    /// Delete expired sessions (cleanup job)
    /// </summary>
    Task<int> DeleteExpiredSessionsAsync();

    /// <summary>
    /// Count active sessions for a user
    /// </summary>
    Task<int> CountActiveSessionsByUserIdAsync(long userId);
}
