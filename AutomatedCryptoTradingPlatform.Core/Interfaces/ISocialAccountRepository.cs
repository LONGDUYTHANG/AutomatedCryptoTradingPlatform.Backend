using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces;

public interface ISocialAccountRepository
{
    Task<SocialAccount?> GetByProviderAsync(string provider, string providerUserId);
    Task<List<SocialAccount>> GetByUserIdAsync(long userId);
    Task<long> CreateAsync(SocialAccount account);
    Task<bool> DeleteAsync(long id);
    Task<bool> ExistsAsync(string provider, string providerUserId);
}
