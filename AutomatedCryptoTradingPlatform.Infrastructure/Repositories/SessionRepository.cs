using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Repositories;
using Dapper;
using Microsoft.Extensions.Configuration;
using Npgsql;

namespace AutomatedCryptoTradingPlatform.Infrastructure.Repositories;

public class SessionRepository : ISessionRepository
{
    private readonly string _connectionString;

    public SessionRepository(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("DefaultConnection") 
            ?? throw new Exception("Database connection string not configured");
    }

    public async Task<AuthSession> CreateAsync(AuthSession session)
    {
        const string sql = @"
            INSERT INTO auth_sessions (user_id, ip_address, user_agent, refresh_token_hash, created_at, last_active_at, expired_at)
            VALUES (@UserId, @IpAddress, @UserAgent, @RefreshTokenHash, @CreatedAt, @LastActiveAt, @ExpiredAt)
            RETURNING id, user_id, ip_address, user_agent, refresh_token_hash, revoked_at, created_at, last_active_at, expired_at";

        using var connection = new NpgsqlConnection(_connectionString);
        var result = await connection.QuerySingleAsync<AuthSession>(sql, session);
        return result;
    }

    public async Task<AuthSession?> GetByIdAsync(long sessionId)
    {
        const string sql = @"
            SELECT id, user_id, ip_address, user_agent, refresh_token_hash, revoked_at, created_at, last_active_at, expired_at
            FROM auth_sessions
            WHERE id = @SessionId";

        using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QuerySingleOrDefaultAsync<AuthSession>(sql, new { SessionId = sessionId });
    }

    public async Task<IEnumerable<AuthSession>> GetActiveSessionsByUserIdAsync(long userId)
    {
        const string sql = @"
            SELECT id, user_id, ip_address, user_agent, refresh_token_hash, revoked_at, created_at, last_active_at, expired_at
            FROM auth_sessions
            WHERE user_id = @UserId 
              AND revoked_at IS NULL 
              AND expired_at > @Now
            ORDER BY last_active_at DESC";

        using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QueryAsync<AuthSession>(sql, new { UserId = userId, Now = DateTime.UtcNow });
    }

    public async Task<bool> UpdateLastActiveAsync(long sessionId)
    {
        const string sql = @"
            UPDATE auth_sessions
            SET last_active_at = @Now
            WHERE id = @SessionId";

        using var connection = new NpgsqlConnection(_connectionString);
        var affected = await connection.ExecuteAsync(sql, new { SessionId = sessionId, Now = DateTime.UtcNow });
        return affected > 0;
    }

    public async Task<bool> RevokeAsync(long sessionId)
    {
        const string sql = @"
            UPDATE auth_sessions
            SET revoked_at = @Now
            WHERE id = @SessionId";

        using var connection = new NpgsqlConnection(_connectionString);
        var affected = await connection.ExecuteAsync(sql, new { SessionId = sessionId, Now = DateTime.UtcNow });
        return affected > 0;
    }

    public async Task<int> RevokeAllByUserIdAsync(long userId)
    {
        const string sql = @"
            UPDATE auth_sessions
            SET revoked_at = @Now
            WHERE user_id = @UserId AND revoked_at IS NULL";

        using var connection = new NpgsqlConnection(_connectionString);
        return await connection.ExecuteAsync(sql, new { UserId = userId, Now = DateTime.UtcNow });
    }

    public async Task<int> DeleteExpiredSessionsAsync()
    {
        const string sql = @"
            DELETE FROM auth_sessions
            WHERE expired_at < @Now";

        using var connection = new NpgsqlConnection(_connectionString);
        return await connection.ExecuteAsync(sql, new { Now = DateTime.UtcNow });
    }

    public async Task<int> CountActiveSessionsByUserIdAsync(long userId)
    {
        const string sql = @"
            SELECT COUNT(*)
            FROM auth_sessions
            WHERE user_id = @UserId 
              AND revoked_at IS NULL 
              AND expired_at > @Now";

        using var connection = new NpgsqlConnection(_connectionString);
        return await connection.ExecuteScalarAsync<int>(sql, new { UserId = userId, Now = DateTime.UtcNow });
    }
}
