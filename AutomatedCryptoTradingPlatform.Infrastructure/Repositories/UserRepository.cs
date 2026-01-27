using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Interfaces;
using Dapper;
using Npgsql;

namespace AutomatedCryptoTradingPlatform.Infrastructure.Repositories;

public class UserRepository : IUserRepository
{
    private readonly string _connectionString;

    public UserRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public async Task<User?> GetByIdAsync(long id)
    {
        const string sql = "SELECT * FROM users WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<User>(sql, new { Id = id });
    }

    public async Task<User?> GetByEmailAsync(string email)
    {
        const string sql = "SELECT * FROM users WHERE email = @Email";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.QueryFirstOrDefaultAsync<User>(sql, new { Email = email });
    }

    public async Task<User?> GetByEmailWithAllRelationsAsync(string email)
    {
        const string sql = @"
            SELECT u.*, p.*, s.*, w.*, t.*
            FROM users u
            LEFT JOIN user_profiles p ON u.id = p.user_id
            LEFT JOIN auth_social_accounts s ON u.id = s.user_id
            LEFT JOIN auth_wallets w ON u.id = w.user_id
            LEFT JOIN auth_2fa t ON u.id = t.user_id
            WHERE u.email = @Email";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        
        var userDictionary = new Dictionary<long, User>();
        
        await connection.QueryAsync<User, UserProfile, SocialAccount, WalletAccount, TwoFactorAuth, User>(
            sql,
            (user, profile, social, wallet, twoFactor) =>
            {
                if (!userDictionary.TryGetValue(user.Id, out var userEntry))
                {
                    userEntry = user;
                    userEntry.Profile = profile;
                    userEntry.TwoFactorAuth = twoFactor;
                    userDictionary.Add(userEntry.Id, userEntry);
                }
                
                if (social != null && !userEntry.SocialAccounts.Any(s => s.Id == social.Id))
                {
                    userEntry.SocialAccounts.Add(social);
                }
                
                if (wallet != null && !userEntry.WalletAccounts.Any(w => w.Id == wallet.Id))
                {
                    userEntry.WalletAccounts.Add(wallet);
                }
                
                return userEntry;
            },
            new { Email = email },
            splitOn: "user_id,id,id,user_id"
        );
        
        return userDictionary.Values.FirstOrDefault();
    }

    public async Task<long> CreateAsync(User user)
    {
        const string sql = @"
            INSERT INTO users (email, username, password_hash, status, role, created_at, updated_at)
            VALUES (@Email, @Username, @PasswordHash, @Status, @Role, @CreatedAt, @UpdatedAt)
            RETURNING id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        return await connection.ExecuteScalarAsync<long>(sql, user);
    }

    public async Task<bool> UpdateAsync(User user)
    {
        const string sql = @"
            UPDATE users 
            SET email = @Email,
                username = @Username,
                password_hash = @PasswordHash,
                status = @Status,
                role = @Role,
                updated_at = @UpdatedAt
            WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, user);
        return rowsAffected > 0;
    }

    public async Task<bool> DeleteAsync(long id)
    {
        const string sql = "DELETE FROM users WHERE id = @Id";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        var rowsAffected = await connection.ExecuteAsync(sql, new { Id = id });
        return rowsAffected > 0;
    }

    public async Task<User?> GetUserWithProfileAsync(long userId)
    {
        const string sql = @"
            SELECT u.*, p.*
            FROM users u
            LEFT JOIN user_profiles p ON u.id = p.user_id
            WHERE u.id = @UserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        
        var userDictionary = new Dictionary<long, User>();
        
        await connection.QueryAsync<User, UserProfile, User>(
            sql,
            (user, profile) =>
            {
                if (!userDictionary.TryGetValue(user.Id, out var userEntry))
                {
                    userEntry = user;
                    userEntry.Profile = profile;
                    userDictionary.Add(userEntry.Id, userEntry);
                }
                return userEntry;
            },
            new { UserId = userId },
            splitOn: "user_id"
        );
        
        return userDictionary.Values.FirstOrDefault();
    }

    public async Task<User?> GetUserWithSocialAccountsAsync(long userId)
    {
        const string sql = @"
            SELECT u.*, s.*
            FROM users u
            LEFT JOIN auth_social_accounts s ON u.id = s.user_id
            WHERE u.id = @UserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        
        var userDictionary = new Dictionary<long, User>();
        
        await connection.QueryAsync<User, SocialAccount, User>(
            sql,
            (user, social) =>
            {
                if (!userDictionary.TryGetValue(user.Id, out var userEntry))
                {
                    userEntry = user;
                    userDictionary.Add(userEntry.Id, userEntry);
                }
                
                if (social != null)
                {
                    userEntry.SocialAccounts.Add(social);
                }
                
                return userEntry;
            },
            new { UserId = userId },
            splitOn: "id"
        );
        
        return userDictionary.Values.FirstOrDefault();
    }

    public async Task<User?> GetUserWithWalletsAsync(long userId)
    {
        const string sql = @"
            SELECT u.*, w.*
            FROM users u
            LEFT JOIN auth_wallets w ON u.id = w.user_id
            WHERE u.id = @UserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        
        var userDictionary = new Dictionary<long, User>();
        
        await connection.QueryAsync<User, WalletAccount, User>(
            sql,
            (user, wallet) =>
            {
                if (!userDictionary.TryGetValue(user.Id, out var userEntry))
                {
                    userEntry = user;
                    userDictionary.Add(userEntry.Id, userEntry);
                }
                
                if (wallet != null)
                {
                    userEntry.WalletAccounts.Add(wallet);
                }
                
                return userEntry;
            },
            new { UserId = userId },
            splitOn: "id"
        );
        
        return userDictionary.Values.FirstOrDefault();
    }

    public async Task<User?> GetUserWithAllRelationsAsync(long userId)
    {
        const string sql = @"
            SELECT u.*, p.*, s.*, w.*, t.*
            FROM users u
            LEFT JOIN user_profiles p ON u.id = p.user_id
            LEFT JOIN auth_social_accounts s ON u.id = s.user_id
            LEFT JOIN auth_wallets w ON u.id = w.user_id
            LEFT JOIN auth_2fa t ON u.id = t.user_id
            WHERE u.id = @UserId";
        
        await using var connection = new NpgsqlConnection(_connectionString);
        
        var userDictionary = new Dictionary<long, User>();
        
        await connection.QueryAsync<User, UserProfile, SocialAccount, WalletAccount, TwoFactorAuth, User>(
            sql,
            (user, profile, social, wallet, twoFactor) =>
            {
                if (!userDictionary.TryGetValue(user.Id, out var userEntry))
                {
                    userEntry = user;
                    userEntry.Profile = profile;
                    userEntry.TwoFactorAuth = twoFactor;
                    userDictionary.Add(userEntry.Id, userEntry);
                }
                
                if (social != null && !userEntry.SocialAccounts.Any(s => s.Id == social.Id))
                {
                    userEntry.SocialAccounts.Add(social);
                }
                
                if (wallet != null && !userEntry.WalletAccounts.Any(w => w.Id == wallet.Id))
                {
                    userEntry.WalletAccounts.Add(wallet);
                }
                
                return userEntry;
            },
            new { UserId = userId },
            splitOn: "user_id,id,id,user_id"
        );
        
        return userDictionary.Values.FirstOrDefault();
    }
}
