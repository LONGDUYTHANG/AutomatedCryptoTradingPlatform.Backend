namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class Bot
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public long? StrategyId { get; set; }
    public long? ExchangeAccountId { get; set; }
    public string? Symbol { get; set; }
    public string? BotType { get; set; }
    public string? Status { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public User User { get; set; } = default!;
    public Strategy? Strategy { get; set; }
    public ExchangeAccount? ExchangeAccount { get; set; }

    public ICollection<BotOrder> Orders { get; set; } = new List<BotOrder>();
    public ICollection<BotTrade> Trades { get; set; } = new List<BotTrade>();
    public ICollection<BotFundMember> FundMembers { get; set; } = new List<BotFundMember>();
}

public class BotOrder
{
    public long Id { get; set; }
    public long BotId { get; set; }
    public string? OrderType { get; set; }
    public string? Side { get; set; }
    public decimal? Price { get; set; }
    public decimal? Quantity { get; set; }
    public string? Status { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public Bot Bot { get; set; } = default!;
    public ICollection<BotTrade> Trades { get; set; } = new List<BotTrade>();
}

public class BotTrade
{
    public long Id { get; set; }
    public long BotId { get; set; }
    public long? OrderId { get; set; }
    public decimal? ExecutedPrice { get; set; }
    public decimal? ExecutedQty { get; set; }
    public decimal? Fee { get; set; }
    public DateTimeOffset ExecutedAt { get; set; } = DateTimeOffset.UtcNow;

    public Bot Bot { get; set; } = default!;
    public BotOrder? Order { get; set; }
}

public class BotFund
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public string? Name { get; set; }
    public decimal? TotalCapital { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public User User { get; set; } = default!;
    public ICollection<BotFundMember> Members { get; set; } = new List<BotFundMember>();
}

public class BotFundMember
{
    public long BotFundId { get; set; }
    public long BotId { get; set; }

    public BotFund BotFund { get; set; } = default!;
    public Bot Bot { get; set; } = default!;
}
