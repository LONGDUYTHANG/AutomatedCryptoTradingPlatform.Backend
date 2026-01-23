namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class SubscriptionDomain
{
    public class Plan
    {
        public long Id { get; set; }
        public string? Name { get; set; }
        public decimal? Price { get; set; }
        public int? BotLimit { get; set; }

        public ICollection<Subscription> Subscriptions { get; set; } = new List<Subscription>();
    }

    public class Subscription
    {
        public long Id { get; set; }
        public long? UserId { get; set; }
        public long? PlanId { get; set; }
        public string? Status { get; set; }
        public DateTimeOffset? StartedAt { get; set; }
        public DateTimeOffset? EndedAt { get; set; }

        public User? User { get; set; }
        public Plan? Plan { get; set; }
        public ICollection<Payment> Payments { get; set; } = new List<Payment>();
    }

    public class Payment
    {
        public long Id { get; set; }
        public long? SubscriptionId { get; set; }
        public decimal? Amount { get; set; }
        public string? Provider { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        public Subscription? Subscription { get; set; }
    }

    public class PerformanceFeeConfig
    {
        public long Id { get; set; }
        public long? UserId { get; set; }
        public decimal? Rate { get; set; }
        public bool HighWaterMark { get; set; } = true;
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        public User? User { get; set; }
        public ICollection<PerformanceFeeRecord> Records { get; set; } = new List<PerformanceFeeRecord>();
    }

    public class PerformanceFeeRecord
    {
        public long Id { get; set; }
        public long? ConfigId { get; set; }
        public long? FollowerId { get; set; }
        public decimal? GrossProfit { get; set; }
        public decimal? FeeAmount { get; set; }
        public DateTimeOffset CalculatedAt { get; set; } = DateTimeOffset.UtcNow; // theo schema
        public bool Settled { get; set; } = false;

        public PerformanceFeeConfig? Config { get; set; }
        public User? Follower { get; set; }
    }
}
