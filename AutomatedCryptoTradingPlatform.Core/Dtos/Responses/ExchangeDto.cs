namespace AutomatedCryptoTradingPlatform.Core.Dtos.Responses;

public class ExchangeDto
{
    public long Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty; // CEX or DEX
}
