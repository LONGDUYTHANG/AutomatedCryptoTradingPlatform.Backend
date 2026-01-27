namespace AutomatedCryptoTradingPlatform.Core.Dtos.Responses;

/// <summary>
/// Response DTO containing nonce for wallet signature
/// </summary>
public class WalletNonceResponseDto
{
    /// <summary>
    /// Wallet address
    /// </summary>
    public required string WalletAddress { get; set; }

    /// <summary>
    /// Random nonce to be signed by wallet
    /// </summary>
    public required string Nonce { get; set; }

    /// <summary>
    /// Message to be signed
    /// </summary>
    public required string Message { get; set; }

    /// <summary>
    /// Nonce expiry time (5 minutes from generation)
    /// </summary>
    public DateTime ExpiresAt { get; set; }
}
