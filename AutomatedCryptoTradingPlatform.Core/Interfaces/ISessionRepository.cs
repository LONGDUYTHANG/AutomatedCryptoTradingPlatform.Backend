using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces;

public interface ISessionRepository
{
    Task<AuthSession?> GetByIdAsync(long id);
    Task<AuthSession?> GetByRefreshTokenHashAsync(string refreshTokenHash);
    Task<List<AuthSession>> GetActiveSessionsByUserIdAsync(long userId);
    Task<long> CreateAsync(AuthSession session);
    Task<bool> UpdateAsync(AuthSession session);
    Task<bool> RevokeAsync(long sessionId);
    Task<bool> RevokeAllUserSessionsAsync(long userId);
    Task<bool> DeleteExpiredSessionsAsync();
}
