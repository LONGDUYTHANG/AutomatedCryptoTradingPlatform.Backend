using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;

namespace AutomatedCryptoTradingPlatform.Core.Interfaces.Services;

/// <summary>
/// Service for wallet authentication (MetaMask, Phantom, etc.)
/// </summary>
public interface IWalletAuthService
{
    /// <summary>
    /// Generate a nonce for wallet signature
    /// </summary>
    /// <param name="walletAddress">Wallet address</param>
    /// <returns>Nonce response with message to sign</returns>
    Task<WalletNonceResponseDto> GenerateNonceAsync(string walletAddress);

    /// <summary>
    /// Verify wallet signature and authenticate user
    /// </summary>
    /// <param name="walletAddress">Wallet address</param>
    /// <param name="signature">Signature from wallet</param>
    /// <param name="nonce">Nonce that was signed</param>
    /// <returns>Auth response with user info</returns>
    Task<AuthResponseDto> VerifySignatureAsync(string walletAddress, string signature, string nonce);

    /// <summary>
    /// Get user by wallet address
    /// </summary>
    Task<Entities.LegacyUser?> GetUserByWalletAsync(string walletAddress);
}
