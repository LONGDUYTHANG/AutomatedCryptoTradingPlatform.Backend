namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class Referral
{
    public class Code
    {
        public long Id { get; set; }
        public long? UserId { get; set; }
        public string? CodeValue { get; set; } // map -> column "code"
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        public User? User { get; set; }
        public ICollection<Activity> Activities { get; set; } = new List<Activity>();
    }

    public class Activity
    {
        public long Id { get; set; }
        public long? ReferrerId { get; set; }
        public long? RefereeId { get; set; }
        public long? ReferralCodeId { get; set; }
        public string? Status { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        public User? Referrer { get; set; }
        public User? Referee { get; set; }
        public Code? ReferralCode { get; set; }
    }

    public class Reward
    {
        public long Id { get; set; }
        public long? ReferrerId { get; set; }
        public decimal? Amount { get; set; }
        public string? Status { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        public User? Referrer { get; set; }
    }
}
