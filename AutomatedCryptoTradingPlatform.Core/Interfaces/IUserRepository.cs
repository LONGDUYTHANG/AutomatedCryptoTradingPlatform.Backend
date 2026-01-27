using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces;

public interface IUserRepository
{
    Task<User?> GetByIdAsync(long id);
    Task<User?> GetByEmailAsync(string email);
    Task<User?> GetByEmailWithAllRelationsAsync(string email);
    Task<long> CreateAsync(User user);
    Task<bool> UpdateAsync(User user);
    Task<bool> DeleteAsync(long id);
    Task<User?> GetUserWithProfileAsync(long userId);
    Task<User?> GetUserWithSocialAccountsAsync(long userId);
    Task<User?> GetUserWithWalletsAsync(long userId);
    Task<User?> GetUserWithAllRelationsAsync(long userId);
}
