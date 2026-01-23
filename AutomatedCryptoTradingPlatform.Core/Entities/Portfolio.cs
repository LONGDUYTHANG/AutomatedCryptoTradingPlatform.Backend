namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class Portfolio
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public long? ExchangeAccountId { get; set; }

    public User User { get; set; } = default!;
    public ExchangeAccount? ExchangeAccount { get; set; }

    public ICollection<PortfolioAsset> Assets { get; set; } = new List<PortfolioAsset>();
    public ICollection<PnlSnapshot> PnlSnapshots { get; set; } = new List<PnlSnapshot>();
}

public class PortfolioAsset
{
    public long PortfolioId { get; set; }
    public string Asset { get; set; } = default!;
    public decimal? Balance { get; set; }
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    public Portfolio Portfolio { get; set; } = default!;
}

public class PnlSnapshot
{
    public long Id { get; set; }
    public long PortfolioId { get; set; }
    public decimal? Pnl { get; set; }
    public DateTimeOffset SnapshotAt { get; set; } = DateTimeOffset.UtcNow;

    public Portfolio Portfolio { get; set; } = default!;
}
