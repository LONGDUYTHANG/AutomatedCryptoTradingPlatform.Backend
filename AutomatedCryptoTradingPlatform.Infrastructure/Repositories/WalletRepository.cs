using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Interfaces;
using Dapper;
using Npgsql;

namespace AutomatedCryptoTradingPlatform.Infrastructure.Repositories;

public class WalletRepository : IWalletRepository
{
    private readonly string _connectionString;

    public WalletRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task<WalletAccount?> GetByWalletAddressAsync(string walletAddress, string? chain = null)
    {
        var sql = "SELECT * FROM auth_wallets WHERE wallet_address = @WalletAddress";
        
        if (!string.IsNullOrEmpty(chain))
        {
            sql += " AND chain = @Chain";
        }
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<WalletAccount>(sql, 
            new { WalletAddress = walletAddress, Chain = chain });
    }

    public async Task<List<WalletAccount>> GetByUserIdAsync(long userId)
    {
        const string sql = "SELECT * FROM auth_wallets WHERE user_id = @UserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var result = await connection.QueryAsync<WalletAccount>(sql, new { UserId = userId });
        return result.ToList();
    }

    public async Task<long> CreateAsync(WalletAccount wallet)
    {
        const string sql = @"
            INSERT INTO auth_wallets (user_id, wallet_address, chain, created_at)
            VALUES (@UserId, @WalletAddress, @Chain, @CreatedAt)
            RETURNING id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.ExecuteScalarAsync<long>(sql, wallet);
    }

    public async Task<bool> DeleteAsync(long id)
    {
        const string sql = "DELETE FROM auth_wallets WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, new { Id = id });
        return rowsAffected > 0;
    }

    public async Task<bool> ExistsAsync(string walletAddress, string? chain = null)
    {
        var sql = "SELECT EXISTS(SELECT 1 FROM auth_wallets WHERE wallet_address = @WalletAddress";
        
        if (!string.IsNullOrEmpty(chain))
        {
            sql += " AND chain = @Chain";
        }
        
        sql += ")";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.ExecuteScalarAsync<bool>(sql, 
            new { WalletAddress = walletAddress, Chain = chain });
    }

    public async Task<long?> GetUserIdByWalletAsync(string walletAddress, string? chain = null)
    {
        var sql = "SELECT user_id FROM auth_wallets WHERE wallet_address = @WalletAddress";
        
        if (!string.IsNullOrEmpty(chain))
        {
            sql += " AND chain = @Chain";
        }
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<long?>(sql, 
            new { WalletAddress = walletAddress, Chain = chain });
    }
}
