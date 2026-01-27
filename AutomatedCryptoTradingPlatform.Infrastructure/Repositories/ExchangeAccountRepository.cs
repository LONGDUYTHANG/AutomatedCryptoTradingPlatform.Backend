using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Interfaces;
using Dapper;
using Npgsql;

namespace AutomatedCryptoTradingPlatform.Infrastructure.Repositories;

public class ExchangeAccountRepository : IExchangeAccountRepository
{
    private readonly string _connectionString;

    public ExchangeAccountRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task<ExchangeAccount?> GetByIdAsync(long id)
    {
        const string sql = "SELECT * FROM exchange_accounts WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<ExchangeAccount>(sql, new { Id = id });
    }

    public async Task<ExchangeAccount?> GetByIdWithRelationsAsync(long id)
    {
        const string sql = @"
            SELECT 
                ea.*,
                e.*,
                ek.*
            FROM exchange_accounts ea
            LEFT JOIN exchanges e ON ea.exchange_id = e.id
            LEFT JOIN exchange_api_keys ek ON ea.id = ek.exchange_account_id
            WHERE ea.id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        
        var accountDict = new Dictionary<long, ExchangeAccount>();
        
        await connection.QueryAsync<ExchangeAccount, Exchange, ExchangeApiKey, ExchangeAccount>(
            sql,
            (account, exchange, apiKey) =>
            {
                if (!accountDict.TryGetValue(account.Id, out var existingAccount))
                {
                    existingAccount = account;
                    existingAccount.Exchange = exchange;
                    accountDict.Add(existingAccount.Id, existingAccount);
                }
                
                if (apiKey != null && !existingAccount.ApiKeys.Any(k => k.Id == apiKey.Id))
                {
                    existingAccount.ApiKeys.Add(apiKey);
                }
                
                return existingAccount;
            },
            new { Id = id },
            splitOn: "id,id"
        );
        
        return accountDict.Values.FirstOrDefault();
    }

    public async Task<List<ExchangeAccount>> GetByUserIdAsync(long userId)
    {
        const string sql = "SELECT * FROM exchange_accounts WHERE user_id = @UserId ORDER BY created_at DESC";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var result = await connection.QueryAsync<ExchangeAccount>(sql, new { UserId = userId });
        return result.ToList();
    }

    public async Task<List<ExchangeAccount>> GetByUserIdWithRelationsAsync(long userId)
    {
        const string sql = @"
            SELECT 
                ea.*,
                e.*,
                ek.*
            FROM exchange_accounts ea
            LEFT JOIN exchanges e ON ea.exchange_id = e.id
            LEFT JOIN exchange_api_keys ek ON ea.id = ek.exchange_account_id
            WHERE ea.user_id = @UserId
            ORDER BY ea.created_at DESC";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        
        var accountDict = new Dictionary<long, ExchangeAccount>();
        
        await connection.QueryAsync<ExchangeAccount, Exchange, ExchangeApiKey, ExchangeAccount>(
            sql,
            (account, exchange, apiKey) =>
            {
                if (!accountDict.TryGetValue(account.Id, out var existingAccount))
                {
                    existingAccount = account;
                    existingAccount.Exchange = exchange;
                    accountDict.Add(existingAccount.Id, existingAccount);
                }
                
                if (apiKey != null && !existingAccount.ApiKeys.Any(k => k.Id == apiKey.Id))
                {
                    existingAccount.ApiKeys.Add(apiKey);
                }
                
                return existingAccount;
            },
            new { UserId = userId },
            splitOn: "id,id"
        );
        
        return accountDict.Values.ToList();
    }

    public async Task<ExchangeAccount?> GetByUserAndExchangeAsync(long userId, long exchangeId)
    {
        const string sql = @"
            SELECT * FROM exchange_accounts 
            WHERE user_id = @UserId AND exchange_id = @ExchangeId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<ExchangeAccount>(
            sql, 
            new { UserId = userId, ExchangeId = exchangeId }
        );
    }

    public async Task<long> CreateAsync(ExchangeAccount account)
    {
        const string sql = @"
            INSERT INTO exchange_accounts (user_id, exchange_id, label, created_at)
            VALUES (@UserId, @ExchangeId, @Label, @CreatedAt)
            RETURNING id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.ExecuteScalarAsync<long>(sql, account);
    }

    public async Task<bool> UpdateAsync(ExchangeAccount account)
    {
        const string sql = @"
            UPDATE exchange_accounts 
            SET label = @Label
            WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, account);
        return rowsAffected > 0;
    }

    public async Task<bool> DeleteAsync(long id)
    {
        const string sql = "DELETE FROM exchange_accounts WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, new { Id = id });
        return rowsAffected > 0;
    }

    public async Task<bool> ExistsAsync(long userId, long exchangeId)
    {
        const string sql = @"
            SELECT COUNT(1) FROM exchange_accounts 
            WHERE user_id = @UserId AND exchange_id = @ExchangeId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var count = await connection.ExecuteScalarAsync<int>(sql, new { UserId = userId, ExchangeId = exchangeId });
        return count > 0;
    }
}
