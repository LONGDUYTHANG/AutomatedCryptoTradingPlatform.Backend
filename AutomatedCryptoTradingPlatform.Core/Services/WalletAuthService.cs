using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Helpers;
using AutomatedCryptoTradingPlatform.Core.Interfaces;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using Microsoft.Extensions.Logging;
using Nethereum.Signer;
using Nethereum.Util;
using System.Text;

namespace AutomatedCryptoTradingPlatform.Core.Services;

/// <summary>
/// Service for wallet authentication (MetaMask, Phantom, etc.)
/// </summary>
public class WalletAuthService : IWalletAuthService
{
    private readonly IRedisService _redisService;
    private readonly IWalletRepository _walletRepository;
    private readonly IUserRepository _userRepository;
    private readonly ILogger<WalletAuthService> _logger;
    private readonly EthereumMessageSigner _messageSigner;

    public WalletAuthService(
        IRedisService redisService,
        IWalletRepository walletRepository,
        IUserRepository userRepository,
        ILogger<WalletAuthService> logger)
    {
        _redisService = redisService;
        _walletRepository = walletRepository;
        _userRepository = userRepository;
        _logger = logger;
        _messageSigner = new EthereumMessageSigner();
    }

    /// <summary>
    /// Generate a nonce for wallet signature
    /// Stores nonce in Redis with 5-minute TTL
    /// </summary>
    public async Task<WalletNonceResponseDto> GenerateNonceAsync(string walletAddress)
    {
        // Validate wallet address
        if (string.IsNullOrWhiteSpace(walletAddress))
        {
            throw new ArgumentException("Wallet address is required");
        }

        // Normalize wallet address to lowercase
        walletAddress = walletAddress.ToLower();

        // Validate Ethereum address format
        if (!walletAddress.StartsWith("0x") || walletAddress.Length != 42)
        {
            throw new ArgumentException("Invalid Ethereum wallet address format");
        }

        // Generate random nonce
        var nonce = Guid.NewGuid().ToString("N"); // 32 character hex string

        // Create message to be signed
        var message = $"Sign this message to authenticate with your wallet.\n\nWallet: {walletAddress}\nNonce: {nonce}\nTimestamp: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}";

        // Store nonce in Redis with 5-minute TTL
        var redisKey = $"wallet_nonce:{walletAddress}";
        await _redisService.SetStringAsync(redisKey, nonce, TimeSpan.FromMinutes(5));

        _logger.LogInformation("Generated nonce for wallet {WalletAddress}", walletAddress);

        return new WalletNonceResponseDto
        {
            WalletAddress = walletAddress,
            Nonce = nonce,
            Message = message,
            ExpiresAt = DateTime.UtcNow.AddMinutes(5)
        };
    }

    /// <summary>
    /// Verify wallet signature and authenticate user
    /// Creates new LegacyUser if wallet address doesn't exist
    /// </summary>
    public async Task<AuthResponseDto> VerifySignatureAsync(string walletAddress, string signature, string nonce)
    {
        // Normalize wallet address
        walletAddress = walletAddress.ToLower();

        _logger.LogInformation("Verifying signature for wallet {WalletAddress}", walletAddress);

        // Retrieve stored nonce from Redis
        var redisKey = $"wallet_nonce:{walletAddress}";
        var storedNonce = await _redisService.GetStringAsync(redisKey);

        if (string.IsNullOrEmpty(storedNonce))
        {
            _logger.LogWarning("Nonce not found or expired for wallet {WalletAddress}", walletAddress);
            throw new UnauthorizedAccessException("Nonce not found or expired. Please request a new nonce.");
        }

        // Verify nonce matches
        if (storedNonce != nonce)
        {
            _logger.LogWarning("Nonce mismatch for wallet {WalletAddress}", walletAddress);
            throw new UnauthorizedAccessException("Invalid nonce");
        }

        // Reconstruct the message that was signed
        var message = $"Sign this message to authenticate with your wallet.\n\nWallet: {walletAddress}\nNonce: {nonce}\nTimestamp: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}";

        try
        {
            // Verify signature
            var recoveredAddress = _messageSigner.EncodeUTF8AndEcRecover(message, signature);

            _logger.LogInformation("Recovered address: {RecoveredAddress}, Expected: {WalletAddress}", 
                recoveredAddress, walletAddress);

            // Compare addresses (case-insensitive)
            if (!string.Equals(recoveredAddress, walletAddress, StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogWarning("Signature verification failed. Recovered: {RecoveredAddress}, Expected: {WalletAddress}",
                    recoveredAddress, walletAddress);
                throw new UnauthorizedAccessException("Invalid signature");
            }

            // Delete used nonce from Redis
            await _redisService.DeleteKeyAsync(redisKey);

            _logger.LogInformation("Signature verified successfully for wallet {WalletAddress}", walletAddress);

            // Get or create user in database
            var existingWallet = await _walletRepository.GetByWalletAddressAsync(walletAddress, "Ethereum");
            
            User user;
            if (existingWallet != null)
            {
                // Load existing user
                user = await _userRepository.GetByIdAsync(existingWallet.UserId)
                    ?? throw new Exception("User not found for wallet");
                
                user.UpdatedAt = DateTime.UtcNow;
                await _userRepository.UpdateAsync(user);
                
                _logger.LogInformation("Existing wallet user authenticated: {UserId}", user.Id);
            }
            else
            {
                // Create new user for this wallet
                user = new User
                {
                    Email = $"{walletAddress.ToLower()}@wallet.local",
                    Username = $"Wallet {walletAddress.Substring(0, 8)}",
                    PasswordHash = null, // Wallet users don't have password
                    Status = "active",
                    Role = "user",
                    CreatedAt = DateTime.UtcNow,
                    UpdatedAt = DateTime.UtcNow
                };

                var userId = await _userRepository.CreateAsync(user);
                user.Id = userId;

                // Create wallet account link
                var walletAccount = new WalletAccount
                {
                    UserId = userId,
                    WalletAddress = walletAddress,
                    Chain = "Ethereum",
                    CreatedAt = DateTime.UtcNow
                };

                await _walletRepository.CreateAsync(walletAccount);

                _logger.LogInformation("Created new wallet user: {UserId} for wallet {WalletAddress}", 
                    userId, walletAddress);
            }

            return new AuthResponseDto
            {
                UserId = UserConversionHelper.GenerateGuidFromLong(user.Id),
                Email = user.Email,
                FullName = user.Username ?? "Wallet User",
                IsEmailVerified = false,
                TwoFactorEnabled = false,
                Require2FA = false
            };
        }
        catch (Exception ex) when (ex is not UnauthorizedAccessException)
        {
            _logger.LogError(ex, "Error verifying wallet signature for {WalletAddress}", walletAddress);
            throw new UnauthorizedAccessException("Failed to verify signature", ex);
        }
    }

    /// <summary>
    /// Get user by wallet address (for internal use)
    /// </summary>
    public async Task<LegacyUser?> GetUserByWalletAsync(string walletAddress)
    {
        walletAddress = walletAddress.ToLower();
        
        var userId = await _walletRepository.GetUserIdByWalletAsync(walletAddress);
        if (userId == null) return null;
        
        var user = await _userRepository.GetUserWithAllRelationsAsync(userId.Value);
        if (user == null) return null;

        return LegacyUser.FromUser(user);
    }
}
