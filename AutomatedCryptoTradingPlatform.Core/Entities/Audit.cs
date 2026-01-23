using System.Text.Json;

namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class Audit
{
    public class Log
    {
        public long Id { get; set; }
        public long? UserId { get; set; }
        public string? Action { get; set; }
        public JsonDocument? Metadata { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        public User? User { get; set; }
    }
}
