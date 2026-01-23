namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class Backtest
{
    public long Id { get; set; }
    public long? StrategyId { get; set; }
    public string? Symbol { get; set; }
    public string? Timeframe { get; set; }
    public DateTimeOffset? StartedAt { get; set; }
    public DateTimeOffset? EndedAt { get; set; }

    public Strategy? Strategy { get; set; }
    public BacktestResult? Result { get; set; }
}

public class BacktestResult
{
    public long BacktestId { get; set; }
    public decimal? Pnl { get; set; }
    public decimal? WinRate { get; set; }
    public decimal? SharpeRatio { get; set; }
    public decimal? MaxDrawdown { get; set; }

    public Backtest Backtest { get; set; } = default!;
}

public class PaperAccount
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public decimal? Balance { get; set; }

    public User User { get; set; } = default!;
}

public class PaperTrade
{
    public long Id { get; set; }
    public long PaperAccountId { get; set; }
    public string? Symbol { get; set; }
    public string? Side { get; set; }
    public decimal? Price { get; set; }
    public decimal? Quantity { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public PaperAccount PaperAccount { get; set; } = default!;
}
