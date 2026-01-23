namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class User
{
    public long Id { get; set; }

    public string Email { get; set; } = default!;
    public string? Username { get; set; }
    public string? PasswordHash { get; set; }
    public string Status { get; set; } = "active";   // active, disabled...
    public string Role { get; set; } = "user";       // user, admin

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    public UserProfile? Profile { get; set; }
    public ICollection<AuthSocialAccount> SocialAccounts { get; set; } = new List<AuthSocialAccount>();
    public ICollection<AuthWallet> Wallets { get; set; } = new List<AuthWallet>();
    public ICollection<AuthSession> Sessions { get; set; } = new List<AuthSession>();
    public Auth2FA? TwoFA { get; set; }

    public ICollection<ExchangeAccount> ExchangeAccounts { get; set; } = new List<ExchangeAccount>();
    public ICollection<Strategy> Strategies { get; set; } = new List<Strategy>();
    public ICollection<Bot> Bots { get; set; } = new List<Bot>();
}

public class UserProfile
{
    public long UserId { get; set; }
    public string? DisplayName { get; set; }
    public string? AvatarUrl { get; set; }
    public string? Country { get; set; }
    public string? Timezone { get; set; }

    public User User { get; set; } = default!;
}

public class AuthSocialAccount
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public string Provider { get; set; } = default!;
    public string ProviderUserId { get; set; } = default!;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public User User { get; set; } = default!;
}

public class AuthWallet
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public string WalletAddress { get; set; } = default!;
    public string? Chain { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public User User { get; set; } = default!;
}

public class AuthSession
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? RefreshTokenHash { get; set; }
    public DateTimeOffset? RevokedAt { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastActiveAt { get; set; }
    public DateTimeOffset? ExpiredAt { get; set; }

    public User User { get; set; } = default!;
}

public class Auth2FA
{
    public long UserId { get; set; }
    public string Secret { get; set; } = default!;
    public bool Enabled { get; set; } = false;

    public User User { get; set; } = default!;
}
