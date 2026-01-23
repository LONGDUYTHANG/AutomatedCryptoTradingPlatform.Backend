namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class MasterTrader
{
    public long UserId { get; set; }
    public bool IsVerified { get; set; } = false;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public User User { get; set; } = default!;
    public ICollection<CopyTrading> Followers { get; set; } = new List<CopyTrading>();
}

public class CopyTrading
{
    public long Id { get; set; }
    public long? FollowerId { get; set; }
    public long? MasterId { get; set; }
    public decimal? AllocationPercent { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public User? Follower { get; set; }
    public MasterTrader? MasterTrader { get; set; }
}

public class LeaderboardStat
{
    public long UserId { get; set; }
    public decimal? TotalPnl { get; set; }
    public decimal? WinRate { get; set; }
    public int? Rank { get; set; }

    public User User { get; set; } = default!;
}
