using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Interfaces;
using Dapper;
using Npgsql;

namespace AutomatedCryptoTradingPlatform.Infrastructure.Repositories;

public class SocialAccountRepository : ISocialAccountRepository
{
    private readonly string _connectionString;

    public SocialAccountRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task<SocialAccount?> GetByProviderAsync(string provider, string providerUserId)
    {
        const string sql = @"
            SELECT * FROM auth_social_accounts 
            WHERE provider = @Provider AND provider_user_id = @ProviderUserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<SocialAccount>(sql, 
            new { Provider = provider, ProviderUserId = providerUserId });
    }

    public async Task<List<SocialAccount>> GetByUserIdAsync(long userId)
    {
        const string sql = "SELECT * FROM auth_social_accounts WHERE user_id = @UserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var result = await connection.QueryAsync<SocialAccount>(sql, new { UserId = userId });
        return result.ToList();
    }

    public async Task<long> CreateAsync(SocialAccount account)
    {
        const string sql = @"
            INSERT INTO auth_social_accounts (user_id, provider, provider_user_id, created_at)
            VALUES (@UserId, @Provider, @ProviderUserId, @CreatedAt)
            RETURNING id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.ExecuteScalarAsync<long>(sql, account);
    }

    public async Task<bool> DeleteAsync(long id)
    {
        const string sql = "DELETE FROM auth_social_accounts WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, new { Id = id });
        return rowsAffected > 0;
    }

    public async Task<bool> ExistsAsync(string provider, string providerUserId)
    {
        const string sql = @"
            SELECT EXISTS(
                SELECT 1 FROM auth_social_accounts 
                WHERE provider = @Provider AND provider_user_id = @ProviderUserId
            )";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.ExecuteScalarAsync<bool>(sql, 
            new { Provider = provider, ProviderUserId = providerUserId });
    }
}
