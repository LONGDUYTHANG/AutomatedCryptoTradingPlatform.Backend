using System.Text.Json;

namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class Alert
{
    public class Rule
    {
        public long Id { get; set; }
        public long? UserId { get; set; }
        public string? Scope { get; set; }
        public JsonDocument? Condition { get; set; }
        public string? Channels { get; set; }
        public bool IsActive { get; set; } = true;
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        public User? User { get; set; }
        public ICollection<Trigger> Triggers { get; set; } = new List<Trigger>();
    }

    public class Trigger
    {
        public long Id { get; set; }
        public long AlertRuleId { get; set; }
        public DateTimeOffset TriggeredAt { get; set; } = DateTimeOffset.UtcNow;
        public JsonDocument? Payload { get; set; }

        public Rule AlertRule { get; set; } = default!;
        public ICollection<Delivery> Deliveries { get; set; } = new List<Delivery>();
    }

    public class Delivery
    {
        public long Id { get; set; }
        public long AlertTriggerId { get; set; }
        public string? Channel { get; set; }
        public string? Status { get; set; }
        public DateTimeOffset? DeliveredAt { get; set; }

        public Trigger AlertTrigger { get; set; } = default!;
    }
}
