using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Interfaces;
using Dapper;
using Npgsql;

namespace AutomatedCryptoTradingPlatform.Infrastructure.Repositories;

public class TwoFactorRepository : ITwoFactorRepository
{
    private readonly string _connectionString;

    public TwoFactorRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task<TwoFactorAuth?> GetByUserIdAsync(long userId)
    {
        const string sql = "SELECT * FROM auth_2fa WHERE user_id = @UserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<TwoFactorAuth>(sql, new { UserId = userId });
    }

    public async Task<bool> CreateAsync(TwoFactorAuth twoFactor)
    {
        const string sql = @"
            INSERT INTO auth_2fa (user_id, secret, enabled)
            VALUES (@UserId, @Secret, @Enabled)
            ON CONFLICT (user_id) DO NOTHING";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, twoFactor);
        return rowsAffected > 0;
    }

    public async Task<bool> UpdateAsync(TwoFactorAuth twoFactor)
    {
        const string sql = @"
            UPDATE auth_2fa 
            SET secret = @Secret,
                enabled = @Enabled
            WHERE user_id = @UserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, twoFactor);
        return rowsAffected > 0;
    }

    public async Task<bool> DeleteAsync(long userId)
    {
        const string sql = "DELETE FROM auth_2fa WHERE user_id = @UserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, new { UserId = userId });
        return rowsAffected > 0;
    }

    public async Task<bool> EnableAsync(long userId)
    {
        const string sql = @"
            UPDATE auth_2fa 
            SET enabled = true 
            WHERE user_id = @UserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, new { UserId = userId });
        return rowsAffected > 0;
    }

    public async Task<bool> DisableAsync(long userId)
    {
        const string sql = @"
            UPDATE auth_2fa 
            SET enabled = false 
            WHERE user_id = @UserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, new { UserId = userId });
        return rowsAffected > 0;
    }
}
