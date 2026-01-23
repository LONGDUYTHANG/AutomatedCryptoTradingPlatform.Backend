using System.Text.Json;

namespace AutomatedCryptoTradingPlatform.Core.Entities;

public class Exchange
{
    public long Id { get; set; }
    public string Name { get; set; } = default!;
    public string? Type { get; set; } // spot/futures...

    public ICollection<ExchangeAccount> Accounts { get; set; } = new List<ExchangeAccount>();
}

public class ExchangeAccount
{
    public long Id { get; set; }
    public long UserId { get; set; }
    public long ExchangeId { get; set; }
    public string? Label { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public User User { get; set; } = default!;
    public Exchange Exchange { get; set; } = default!;
    public ICollection<ExchangeApiKey> ApiKeys { get; set; } = new List<ExchangeApiKey>();
}

public class ExchangeApiKey
{
    public long Id { get; set; }
    public long ExchangeAccountId { get; set; }
    public string Label { get; set; } = default!;
    public string ApiKey { get; set; } = default!;
    public string ApiSecret { get; set; } = default!;
    public string Paraphase { get; set; } = default!;
    public JsonDocument? Permissions { get; set; }
    public string Status { get; set; } = "active";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public ExchangeAccount ExchangeAccount { get; set; } = default!;
}
