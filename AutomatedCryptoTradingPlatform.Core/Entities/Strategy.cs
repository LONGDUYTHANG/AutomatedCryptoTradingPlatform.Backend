using System.Text.Json;

namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class Strategy
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public string Name { get; set; } = default!;
    public string? Description { get; set; }
    public bool IsPublic { get; set; } = false;
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public User User { get; set; } = default!;
    public ICollection<StrategyIndicator> Indicators { get; set; } = new List<StrategyIndicator>();
    public ICollection<StrategyCondition> Conditions { get; set; } = new List<StrategyCondition>();
}

public class StrategyIndicator
{
    public long Id { get; set; }
    public long StrategyId { get; set; }
    public string? Indicator { get; set; }
    public JsonDocument? Config { get; set; }

    public Strategy Strategy { get; set; } = default!;
}

public class StrategyCondition
{
    public long Id { get; set; }
    public long StrategyId { get; set; }
    public string? ConditionType { get; set; }
    public string? Expression { get; set; }

    public Strategy Strategy { get; set; } = default!;
}
