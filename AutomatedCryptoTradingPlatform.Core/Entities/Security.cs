using System.Text.Json;

namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class Security
{
    public class UserActivityLog
    {
        public long Id { get; set; }
        public long? UserId { get; set; }
        public string? Action { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        public User? User { get; set; }
    }

    public class Event
    {
        public long Id { get; set; }
        public long? UserId { get; set; }
        public string? EventType { get; set; }
        public string? Severity { get; set; }
        public JsonDocument? Metadata { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        public User? User { get; set; }
    }
}
