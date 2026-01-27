using AutomatedCryptoTradingPlatform.Core.Entities;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces;

public interface IWalletRepository
{
    Task<WalletAccount?> GetByWalletAddressAsync(string walletAddress, string? chain = null);
    Task<List<WalletAccount>> GetByUserIdAsync(long userId);
    Task<long> CreateAsync(WalletAccount wallet);
    Task<bool> DeleteAsync(long id);
    Task<bool> ExistsAsync(string walletAddress, string? chain = null);
    Task<long?> GetUserIdByWalletAsync(string walletAddress, string? chain = null);
}
