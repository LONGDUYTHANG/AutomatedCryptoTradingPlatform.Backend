namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class Risk
{
    public class Rule
    {
        public long Id { get; set; }
        public string? Scope { get; set; }
        public long? ScopeId { get; set; }
        public string? RuleType { get; set; }
        public decimal? Threshold { get; set; }
        public string? Action { get; set; }
        public bool IsActive { get; set; } = true;
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        public ICollection<Violation> Violations { get; set; } = new List<Violation>();
    }

    public class Violation
    {
        public long Id { get; set; }
        public long? RiskRuleId { get; set; }
        public decimal? CurrentValue { get; set; }
        public DateTimeOffset ViolatedAt { get; set; } = DateTimeOffset.UtcNow;

        public Rule? RiskRule { get; set; }
        public ICollection<Action> Actions { get; set; } = new List<Action>();
    }

    public class Action
    {
        public long Id { get; set; }
        public long? ViolationId { get; set; }
        public string? ExecutedAction { get; set; }
        public DateTimeOffset ExecutedAt { get; set; } = DateTimeOffset.UtcNow;

        public Violation? Violation { get; set; }
    }
}
