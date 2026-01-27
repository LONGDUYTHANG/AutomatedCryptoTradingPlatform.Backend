using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces;

public interface ITwoFactorRepository
{
    Task<TwoFactorAuth?> GetByUserIdAsync(long userId);
    Task<bool> CreateAsync(TwoFactorAuth twoFactor);
    Task<bool> UpdateAsync(TwoFactorAuth twoFactor);
    Task<bool> DeleteAsync(long userId);
    Task<bool> EnableAsync(long userId);
    Task<bool> DisableAsync(long userId);
}
