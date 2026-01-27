using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Interfaces;
using Dapper;
using Npgsql;

namespace AutomatedCryptoTradingPlatform.Infrastructure.Repositories;

public class ExchangeRepository : IExchangeRepository
{
    private readonly string _connectionString;

    public ExchangeRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task<Exchange?> GetByIdAsync(long id)
    {
        const string sql = "SELECT * FROM exchanges WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<Exchange>(sql, new { Id = id });
    }

    public async Task<Exchange?> GetByNameAsync(string name)
    {
        const string sql = "SELECT * FROM exchanges WHERE name = @Name";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<Exchange>(sql, new { Name = name });
    }

    public async Task<List<Exchange>> GetAllAsync()
    {
        const string sql = "SELECT * FROM exchanges ORDER BY name";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var result = await connection.QueryAsync<Exchange>(sql);
        return result.ToList();
    }

    public async Task<List<Exchange>> GetByTypeAsync(string type)
    {
        const string sql = "SELECT * FROM exchanges WHERE type = @Type ORDER BY name";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var result = await connection.QueryAsync<Exchange>(sql, new { Type = type });
        return result.ToList();
    }

    public async Task<long> CreateAsync(Exchange exchange)
    {
        const string sql = @"
            INSERT INTO exchanges (name, type)
            VALUES (@Name, @Type)
            RETURNING id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.ExecuteScalarAsync<long>(sql, exchange);
    }

    public async Task<bool> UpdateAsync(Exchange exchange)
    {
        const string sql = @"
            UPDATE exchanges 
            SET name = @Name, type = @Type
            WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, exchange);
        return rowsAffected > 0;
    }

    public async Task<bool> DeleteAsync(long id)
    {
        const string sql = "DELETE FROM exchanges WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, new { Id = id });
        return rowsAffected > 0;
    }
}
