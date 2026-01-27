using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Interfaces;
using Dapper;
using Npgsql;

namespace AutomatedCryptoTradingPlatform.Infrastructure.Repositories;

public class ExchangeApiKeyRepository : IExchangeApiKeyRepository
{
    private readonly string _connectionString;

    public ExchangeApiKeyRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task<ExchangeApiKey?> GetByIdAsync(long id)
    {
        const string sql = "SELECT * FROM exchange_api_keys WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<ExchangeApiKey>(sql, new { Id = id });
    }

    public async Task<ExchangeApiKey?> GetByIdWithRelationsAsync(long id)
    {
        const string sql = @"
            SELECT 
                ek.*,
                ea.*,
                e.*
            FROM exchange_api_keys ek
            INNER JOIN exchange_accounts ea ON ek.exchange_account_id = ea.id
            INNER JOIN exchanges e ON ea.exchange_id = e.id
            WHERE ek.id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        
        ExchangeApiKey? apiKey = null;
        
        await connection.QueryAsync<ExchangeApiKey, ExchangeAccount, Exchange, ExchangeApiKey>(
            sql,
            (key, account, exchange) =>
            {
                apiKey = key;
                apiKey.Account = account;
                apiKey.Account.Exchange = exchange;
                return apiKey;
            },
            new { Id = id },
            splitOn: "id,id"
        );
        
        return apiKey;
    }

    public async Task<List<ExchangeApiKey>> GetByAccountIdAsync(long accountId)
    {
        const string sql = @"
            SELECT * FROM exchange_api_keys 
            WHERE exchange_account_id = @AccountId 
            ORDER BY created_at DESC";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var result = await connection.QueryAsync<ExchangeApiKey>(sql, new { AccountId = accountId });
        return result.ToList();
    }

    public async Task<List<ExchangeApiKey>> GetActiveByAccountIdAsync(long accountId)
    {
        const string sql = @"
            SELECT * FROM exchange_api_keys 
            WHERE exchange_account_id = @AccountId AND status = 'active'
            ORDER BY created_at DESC";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var result = await connection.QueryAsync<ExchangeApiKey>(sql, new { AccountId = accountId });
        return result.ToList();
    }

    public async Task<List<ExchangeApiKey>> GetByUserIdAsync(long userId)
    {
        const string sql = @"
            SELECT ek.*
            FROM exchange_api_keys ek
            INNER JOIN exchange_accounts ea ON ek.exchange_account_id = ea.id
            WHERE ea.user_id = @UserId
            ORDER BY ek.created_at DESC";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var result = await connection.QueryAsync<ExchangeApiKey>(sql, new { UserId = userId });
        return result.ToList();
    }

    public async Task<List<ExchangeApiKey>> GetActiveByUserIdAsync(long userId)
    {
        const string sql = @"
            SELECT ek.*
            FROM exchange_api_keys ek
            INNER JOIN exchange_accounts ea ON ek.exchange_account_id = ea.id
            WHERE ea.user_id = @UserId AND ek.status = 'active'
            ORDER BY ek.created_at DESC";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var result = await connection.QueryAsync<ExchangeApiKey>(sql, new { UserId = userId });
        return result.ToList();
    }

    public async Task<long> CreateAsync(ExchangeApiKey apiKey)
    {
        const string sql = @"
            INSERT INTO exchange_api_keys 
            (exchange_account_id, label, api_key, api_secret, passphrase, permissions, status, created_at)
            VALUES 
            (@ExchangeAccountId, @Label, @ApiKey, @ApiSecret, @Passphrase, @Permissions, @Status, @CreatedAt)
            RETURNING id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.ExecuteScalarAsync<long>(sql, apiKey);
    }

    public async Task<bool> UpdateAsync(ExchangeApiKey apiKey)
    {
        const string sql = @"
            UPDATE exchange_api_keys 
            SET 
                label = @Label,
                api_key = @ApiKey,
                api_secret = @ApiSecret,
                passphrase = @Passphrase,
                permissions = @Permissions,
                status = @Status
            WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, apiKey);
        return rowsAffected > 0;
    }

    public async Task<bool> DeleteAsync(long id)
    {
        const string sql = "DELETE FROM exchange_api_keys WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, new { Id = id });
        return rowsAffected > 0;
    }

    public async Task<bool> UpdateStatusAsync(long id, string status)
    {
        const string sql = "UPDATE exchange_api_keys SET status = @Status WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, new { Id = id, Status = status });
        return rowsAffected > 0;
    }

    public async Task<bool> UpdateLastVerifiedAsync(long id, DateTime timestamp)
    {
        // Note: last_verified is not in DB schema, but we keep this for backward compatibility
        // This is a no-op for now
        return await Task.FromResult(true);
    }

    public async Task<bool> BelongsToUserAsync(long apiKeyId, long userId)
    {
        const string sql = @"
            SELECT COUNT(1)
            FROM exchange_api_keys ek
            INNER JOIN exchange_accounts ea ON ek.exchange_account_id = ea.id
            WHERE ek.id = @ApiKeyId AND ea.user_id = @UserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var count = await connection.ExecuteScalarAsync<int>(sql, new { ApiKeyId = apiKeyId, UserId = userId });
        return count > 0;
    }
}
