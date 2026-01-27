namespace AutomatedCryptoTradingPlatform.Core.Entities;

/// <summary>
/// Auth session entity - Source of truth for user sessions
/// Stored in PostgreSQL database
/// </summary>
public class AuthSession
{
    /// <summary>
    /// Primary key - Session ID (used in cookie)
    /// </summary>
    public long Id { get; set; }

    /// <summary>
    /// User ID reference
    /// </summary>
    public long UserId { get; set; }

    /// <summary>
    /// Client IP address
    /// </summary>
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>
    /// User agent (browser/device info)
    /// </summary>
    public string UserAgent { get; set; } = string.Empty;

    /// <summary>
    /// Hash of refresh token (optional, for long session validation)
    /// </summary>
    public string? RefreshTokenHash { get; set; }

    /// <summary>
    /// When session was revoked (logout/security)
    /// </summary>
    public DateTime? RevokedAt { get; set; }

    /// <summary>
    /// Session creation time
    /// </summary>
    public DateTime CreatedAt { get; set; }

    /// <summary>
    /// Last activity timestamp
    /// </summary>
    public DateTime LastActiveAt { get; set; }

    /// <summary>
    /// Session expiration time
    /// </summary>
    public DateTime ExpiredAt { get; set; }

    /// <summary>
    /// Check if session is active
    /// </summary>
    public bool IsActive => RevokedAt == null && DateTime.UtcNow < ExpiredAt;

    /// <summary>
    /// Check if session is expired
    /// </summary>
    public bool IsExpired => DateTime.UtcNow >= ExpiredAt;

    /// <summary>
    /// Check if session is revoked
    /// </summary>
    public bool IsRevoked => RevokedAt != null;
}
