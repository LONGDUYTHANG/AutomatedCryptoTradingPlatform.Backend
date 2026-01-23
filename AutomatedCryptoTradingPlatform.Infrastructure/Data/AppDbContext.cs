using AutomatedCryptoTradingPlatform.Core.Entities;
using Microsoft.EntityFrameworkCore;

namespace AutomatedCryptoTradingPlatform.Infrastructure.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    // ===== USERS / AUTH =====
    public DbSet<User> Users => Set<User>();
    public DbSet<UserProfile> UserProfiles => Set<UserProfile>();
    public DbSet<AuthSocialAccount> AuthSocialAccounts => Set<AuthSocialAccount>();
    public DbSet<AuthWallet> AuthWallets => Set<AuthWallet>();
    public DbSet<AuthSession> AuthSessions => Set<AuthSession>();
    public DbSet<Auth2FA> Auth2FAs => Set<Auth2FA>();

    // ===== EXCHANGE =====
    public DbSet<Exchange> Exchanges => Set<Exchange>();
    public DbSet<ExchangeAccount> ExchangeAccounts => Set<ExchangeAccount>();
    public DbSet<ExchangeApiKey> ExchangeApiKeys => Set<ExchangeApiKey>();

    // ===== STRATEGY =====
    public DbSet<Strategy> Strategies => Set<Strategy>();
    public DbSet<StrategyIndicator> StrategyIndicators => Set<StrategyIndicator>();
    public DbSet<StrategyCondition> StrategyConditions => Set<StrategyCondition>();

    // ===== BOT =====
    public DbSet<Bot> Bots => Set<Bot>();
    public DbSet<BotOrder> BotOrders => Set<BotOrder>();
    public DbSet<BotTrade> BotTrades => Set<BotTrade>();
    public DbSet<BotFund> BotFunds => Set<BotFund>();
    public DbSet<BotFundMember> BotFundMembers => Set<BotFundMember>();

    // ===== BACKTEST / PAPER =====
    public DbSet<Backtest> Backtests => Set<Backtest>();
    public DbSet<BacktestResult> BacktestResults => Set<BacktestResult>();
    public DbSet<PaperAccount> PaperAccounts => Set<PaperAccount>();
    public DbSet<PaperTrade> PaperTrades => Set<PaperTrade>();

    // ===== PORTFOLIO =====
    public DbSet<Portfolio> Portfolios => Set<Portfolio>();
    public DbSet<PortfolioAsset> PortfolioAssets => Set<PortfolioAsset>();
    public DbSet<PnlSnapshot> PnlSnapshots => Set<PnlSnapshot>();

    // ===== COPY TRADING =====
    public DbSet<MasterTrader> MasterTraders => Set<MasterTrader>();
    public DbSet<CopyTrading> CopyTradings => Set<CopyTrading>();
    public DbSet<LeaderboardStat> LeaderboardStats => Set<LeaderboardStat>();

    // ===== ALERT / SECURITY / RISK / REFERRAL / SUBSCRIPTION / AUDIT (nested) =====
    public DbSet<Alert.Rule> AlertRules => Set<Alert.Rule>();
    public DbSet<Alert.Trigger> AlertTriggers => Set<Alert.Trigger>();
    public DbSet<Alert.Delivery> AlertDeliveries => Set<Alert.Delivery>();

    public DbSet<Security.UserActivityLog> UserActivityLogs => Set<Security.UserActivityLog>();
    public DbSet<Security.Event> SecurityEvents => Set<Security.Event>();

    public DbSet<Risk.Rule> RiskRules => Set<Risk.Rule>();
    public DbSet<Risk.Violation> RiskViolations => Set<Risk.Violation>();
    public DbSet<Risk.Action> RiskActions => Set<Risk.Action>();

    public DbSet<Referral.Code> ReferralCodes => Set<Referral.Code>();
    public DbSet<Referral.Activity> ReferralActivities => Set<Referral.Activity>();
    public DbSet<Referral.Reward> AffiliateRewards => Set<Referral.Reward>();

    public DbSet<SubscriptionDomain.Plan> Plans => Set<SubscriptionDomain.Plan>();
    public DbSet<SubscriptionDomain.Subscription> Subscriptions => Set<SubscriptionDomain.Subscription>();
    public DbSet<SubscriptionDomain.Payment> Payments => Set<SubscriptionDomain.Payment>();
    public DbSet<SubscriptionDomain.PerformanceFeeConfig> PerformanceFeeConfigs => Set<SubscriptionDomain.PerformanceFeeConfig>();
    public DbSet<SubscriptionDomain.PerformanceFeeRecord> PerformanceFeeRecords => Set<SubscriptionDomain.PerformanceFeeRecord>();

    public DbSet<Audit.Log> AuditLogs => Set<Audit.Log>();

    // ===== EXTRA (theo entities bạn gửi) =====
    public DbSet<Otp> Otps => Set<Otp>();
    public DbSet<ExchangeKey> ExchangeKeys => Set<ExchangeKey>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Extension
        modelBuilder.HasPostgresExtension("uuid-ossp");

        // ---------- USERS ----------
        modelBuilder.Entity<User>(b =>
        {
            b.ToTable("users");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.Email).HasColumnName("email").HasMaxLength(255).IsRequired();
            b.HasIndex(x => x.Email).IsUnique();

            b.Property(x => x.Username).HasColumnName("username").HasMaxLength(100);
            b.Property(x => x.PasswordHash).HasColumnName("password_hash");
            b.Property(x => x.Status).HasColumnName("status").HasMaxLength(20).HasDefaultValue("active");
            b.Property(x => x.Role).HasColumnName("role").HasMaxLength(20).HasDefaultValue("user");

            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<UserProfile>(b =>
        {
            b.ToTable("user_profiles");
            b.HasKey(x => x.UserId);
            b.Property(x => x.UserId).HasColumnName("user_id");

            b.Property(x => x.DisplayName).HasColumnName("display_name").HasMaxLength(100);
            b.Property(x => x.AvatarUrl).HasColumnName("avatar_url");
            b.Property(x => x.Country).HasColumnName("country").HasMaxLength(50);
            b.Property(x => x.Timezone).HasColumnName("timezone").HasMaxLength(50);

            b.HasOne(x => x.User)
             .WithOne(x => x.Profile)
             .HasForeignKey<UserProfile>(x => x.UserId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AuthSocialAccount>(b =>
        {
            b.ToTable("auth_social_accounts");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.Provider).HasColumnName("provider").HasMaxLength(50).IsRequired();
            b.Property(x => x.ProviderUserId).HasColumnName("provider_user_id").HasMaxLength(255).IsRequired();
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
            b.HasIndex(x => new { x.Provider, x.ProviderUserId }).IsUnique();

            b.HasOne(x => x.User)
             .WithMany(x => x.SocialAccounts)
             .HasForeignKey(x => x.UserId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AuthWallet>(b =>
        {
            b.ToTable("auth_wallets");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.WalletAddress).HasColumnName("wallet_address").HasMaxLength(255).IsRequired();
            b.Property(x => x.Chain).HasColumnName("chain").HasMaxLength(50);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
            b.HasIndex(x => new { x.WalletAddress, x.Chain }).IsUnique();

            b.HasOne(x => x.User)
             .WithMany(x => x.Wallets)
             .HasForeignKey(x => x.UserId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<AuthSession>(b =>
        {
            b.ToTable("auth_sessions");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.IpAddress).HasColumnName("ip_address").HasMaxLength(64);
            b.Property(x => x.UserAgent).HasColumnName("user_agent");
            b.Property(x => x.RefreshTokenHash).HasColumnName("refresh_token_hash");
            b.Property(x => x.RevokedAt).HasColumnName("revoked_at");
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
            b.Property(x => x.LastActiveAt).HasColumnName("last_active_at");
            b.Property(x => x.ExpiredAt).HasColumnName("expired_at");

            b.HasOne(x => x.User)
             .WithMany(x => x.Sessions)
             .HasForeignKey(x => x.UserId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<Auth2FA>(b =>
        {
            b.ToTable("auth_2fa");
            b.HasKey(x => x.UserId);

            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.Secret).HasColumnName("secret").IsRequired();
            b.Property(x => x.Enabled).HasColumnName("enabled").HasDefaultValue(false);

            b.HasOne(x => x.User)
             .WithOne(x => x.TwoFA)
             .HasForeignKey<Auth2FA>(x => x.UserId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // ---------- EXCHANGES ----------
        modelBuilder.Entity<Exchange>(b =>
        {
            b.ToTable("exchanges");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.Name).HasColumnName("name").HasMaxLength(50).IsRequired();
            b.HasIndex(x => x.Name).IsUnique();
            b.Property(x => x.Type).HasColumnName("type").HasMaxLength(20);
        });

        modelBuilder.Entity<ExchangeAccount>(b =>
        {
            b.ToTable("exchange_accounts");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.ExchangeId).HasColumnName("exchange_id");
            b.Property(x => x.Label).HasColumnName("label").HasMaxLength(100);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");

            b.HasOne(x => x.User)
             .WithMany(x => x.ExchangeAccounts)
             .HasForeignKey(x => x.UserId)
             .OnDelete(DeleteBehavior.Cascade);

            b.HasOne(x => x.Exchange)
             .WithMany(x => x.Accounts)
             .HasForeignKey(x => x.ExchangeId);
        });

        modelBuilder.Entity<ExchangeApiKey>(b =>
        {
            b.ToTable("exchange_api_keys");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.ExchangeAccountId).HasColumnName("exchange_account_id");
            b.Property(x => x.Label).HasColumnName("label").IsRequired();
            b.Property(x => x.ApiKey).HasColumnName("api_key").IsRequired();
            b.Property(x => x.ApiSecret).HasColumnName("api_secret").IsRequired();
            b.Property(x => x.Paraphase).HasColumnName("paraphase").IsRequired();
            b.Property(x => x.Permissions).HasColumnName("permissions").HasColumnType("jsonb");
            b.Property(x => x.Status).HasColumnName("status").HasMaxLength(20).HasDefaultValue("active");
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");

            b.HasOne(x => x.ExchangeAccount)
             .WithMany(x => x.ApiKeys)
             .HasForeignKey(x => x.ExchangeAccountId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // ---------- STRATEGY ----------
        modelBuilder.Entity<Strategy>(b =>
        {
            b.ToTable("strategies");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.Name).HasColumnName("name").HasMaxLength(100).IsRequired();
            b.Property(x => x.Description).HasColumnName("description");
            b.Property(x => x.IsPublic).HasColumnName("is_public").HasDefaultValue(false);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");

            b.HasOne(x => x.User)
             .WithMany(x => x.Strategies)
             .HasForeignKey(x => x.UserId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<StrategyIndicator>(b =>
        {
            b.ToTable("strategy_indicators");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.StrategyId).HasColumnName("strategy_id");
            b.Property(x => x.Indicator).HasColumnName("indicator").HasMaxLength(50);
            b.Property(x => x.Config).HasColumnName("config").HasColumnType("jsonb");

            b.HasOne(x => x.Strategy)
             .WithMany(x => x.Indicators)
             .HasForeignKey(x => x.StrategyId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<StrategyCondition>(b =>
        {
            b.ToTable("strategy_conditions");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.StrategyId).HasColumnName("strategy_id");
            b.Property(x => x.ConditionType).HasColumnName("condition_type").HasMaxLength(20);
            b.Property(x => x.Expression).HasColumnName("expression");

            b.HasOne(x => x.Strategy)
             .WithMany(x => x.Conditions)
             .HasForeignKey(x => x.StrategyId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // ---------- BOT ----------
        modelBuilder.Entity<Bot>(b =>
        {
            b.ToTable("bots");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.StrategyId).HasColumnName("strategy_id");
            b.Property(x => x.ExchangeAccountId).HasColumnName("exchange_account_id");
            b.Property(x => x.Symbol).HasColumnName("symbol").HasMaxLength(50);
            b.Property(x => x.BotType).HasColumnName("bot_type").HasMaxLength(30);
            b.Property(x => x.Status).HasColumnName("status").HasMaxLength(20);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");

            b.HasOne(x => x.User).WithMany(x => x.Bots).HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
            b.HasOne(x => x.Strategy).WithMany().HasForeignKey(x => x.StrategyId);
            b.HasOne(x => x.ExchangeAccount).WithMany().HasForeignKey(x => x.ExchangeAccountId);
        });

        modelBuilder.Entity<BotOrder>(b =>
        {
            b.ToTable("bot_orders");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.BotId).HasColumnName("bot_id");
            b.Property(x => x.OrderType).HasColumnName("order_type").HasMaxLength(20);
            b.Property(x => x.Side).HasColumnName("side").HasMaxLength(10);
            b.Property(x => x.Price).HasColumnName("price").HasPrecision(20, 8);
            b.Property(x => x.Quantity).HasColumnName("quantity").HasPrecision(20, 8);
            b.Property(x => x.Status).HasColumnName("status").HasMaxLength(20);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");

            b.HasOne(x => x.Bot).WithMany(x => x.Orders).HasForeignKey(x => x.BotId).OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<BotTrade>(b =>
        {
            b.ToTable("bot_trades");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.BotId).HasColumnName("bot_id");
            b.Property(x => x.OrderId).HasColumnName("order_id");
            b.Property(x => x.ExecutedPrice).HasColumnName("executed_price").HasPrecision(20, 8);
            b.Property(x => x.ExecutedQty).HasColumnName("executed_qty").HasPrecision(20, 8);
            b.Property(x => x.Fee).HasColumnName("fee").HasPrecision(20, 8);
            b.Property(x => x.ExecutedAt).HasColumnName("executed_at").HasDefaultValueSql("now()");

            b.HasOne(x => x.Bot).WithMany(x => x.Trades).HasForeignKey(x => x.BotId).OnDelete(DeleteBehavior.Cascade);
            b.HasOne(x => x.Order).WithMany(x => x.Trades).HasForeignKey(x => x.OrderId);
        });

        modelBuilder.Entity<BotFund>(b =>
        {
            b.ToTable("bot_funds");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.Name).HasColumnName("name").HasMaxLength(100);
            b.Property(x => x.TotalCapital).HasColumnName("total_capital").HasPrecision(20, 8);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<BotFundMember>(b =>
        {
            b.ToTable("bot_fund_members");
            b.HasKey(x => new { x.BotFundId, x.BotId });

            b.Property(x => x.BotFundId).HasColumnName("bot_fund_id");
            b.Property(x => x.BotId).HasColumnName("bot_id");

            b.HasOne(x => x.BotFund).WithMany(x => x.Members).HasForeignKey(x => x.BotFundId).OnDelete(DeleteBehavior.Cascade);
            b.HasOne(x => x.Bot).WithMany(x => x.FundMembers).HasForeignKey(x => x.BotId).OnDelete(DeleteBehavior.Cascade);
        });

        // ---------- BACKTEST / PAPER ----------
        modelBuilder.Entity<Backtest>(b =>
        {
            b.ToTable("backtests");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.StrategyId).HasColumnName("strategy_id");
            b.Property(x => x.Symbol).HasColumnName("symbol").HasMaxLength(50);
            b.Property(x => x.Timeframe).HasColumnName("timeframe").HasMaxLength(20);
            b.Property(x => x.StartedAt).HasColumnName("started_at");
            b.Property(x => x.EndedAt).HasColumnName("ended_at");
        });

        modelBuilder.Entity<BacktestResult>(b =>
        {
            b.ToTable("backtest_results");
            b.HasKey(x => x.BacktestId);

            b.Property(x => x.BacktestId).HasColumnName("backtest_id");
            b.Property(x => x.Pnl).HasColumnName("pnl").HasPrecision(20, 8);
            b.Property(x => x.WinRate).HasColumnName("win_rate").HasPrecision(5, 2);
            b.Property(x => x.SharpeRatio).HasColumnName("sharpe_ratio").HasPrecision(6, 3);
            b.Property(x => x.MaxDrawdown).HasColumnName("max_drawdown").HasPrecision(6, 3);

            b.HasOne(x => x.Backtest)
             .WithOne(x => x.Result)
             .HasForeignKey<BacktestResult>(x => x.BacktestId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<PaperAccount>(b =>
        {
            b.ToTable("paper_accounts");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.Balance).HasColumnName("balance").HasPrecision(20, 8);

            b.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId);
        });

        modelBuilder.Entity<PaperTrade>(b =>
        {
            b.ToTable("paper_trades");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.PaperAccountId).HasColumnName("paper_account_id");
            b.Property(x => x.Symbol).HasColumnName("symbol").HasMaxLength(50);
            b.Property(x => x.Side).HasColumnName("side").HasMaxLength(10);
            b.Property(x => x.Price).HasColumnName("price").HasPrecision(20, 8);
            b.Property(x => x.Quantity).HasColumnName("quantity").HasPrecision(20, 8);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        // ---------- PORTFOLIO ----------
        modelBuilder.Entity<Portfolio>(b =>
        {
            b.ToTable("portfolios");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.ExchangeAccountId).HasColumnName("exchange_account_id");
        });

        modelBuilder.Entity<PortfolioAsset>(b =>
        {
            b.ToTable("portfolio_assets");
            b.HasKey(x => new { x.PortfolioId, x.Asset });

            b.Property(x => x.PortfolioId).HasColumnName("portfolio_id");
            b.Property(x => x.Asset).HasColumnName("asset").HasMaxLength(20);
            b.Property(x => x.Balance).HasColumnName("balance").HasPrecision(20, 8);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<PnlSnapshot>(b =>
        {
            b.ToTable("pnl_snapshots");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.PortfolioId).HasColumnName("portfolio_id");
            b.Property(x => x.Pnl).HasColumnName("pnl").HasPrecision(20, 8);
            b.Property(x => x.SnapshotAt).HasColumnName("snapshot_at").HasDefaultValueSql("now()");
        });

        // ---------- COPY TRADING ----------
        modelBuilder.Entity<MasterTrader>(b =>
        {
            b.ToTable("master_traders");
            b.HasKey(x => x.UserId);
            b.Property(x => x.UserId).HasColumnName("user_id");

            b.Property(x => x.IsVerified).HasColumnName("is_verified").HasDefaultValue(false);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<CopyTrading>(b =>
        {
            b.ToTable("copy_trading");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();

            b.Property(x => x.FollowerId).HasColumnName("follower_id");
            b.Property(x => x.MasterId).HasColumnName("master_id");
            b.Property(x => x.AllocationPercent).HasColumnName("allocation_percent").HasPrecision(5, 2);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<LeaderboardStat>(b =>
        {
            b.ToTable("leaderboard_stats");
            b.HasKey(x => x.UserId);
            b.Property(x => x.UserId).HasColumnName("user_id");

            b.Property(x => x.TotalPnl).HasColumnName("total_pnl").HasPrecision(20, 8);
            b.Property(x => x.WinRate).HasColumnName("win_rate").HasPrecision(5, 2);
            b.Property(x => x.Rank).HasColumnName("rank");
        });

        // ---------- ALERT / SECURITY / RISK / REFERRAL / SUBSCRIPTION / AUDIT ----------
        // (giữ đúng table name + jsonb + precision)
        modelBuilder.Entity<Alert.Rule>(b =>
        {
            b.ToTable("alert_rules");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.Scope).HasColumnName("scope").HasMaxLength(50);
            b.Property(x => x.Condition).HasColumnName("condition").HasColumnType("jsonb");
            b.Property(x => x.Channels).HasColumnName("channels").HasMaxLength(50);
            b.Property(x => x.IsActive).HasColumnName("is_active").HasDefaultValue(true);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<Alert.Trigger>(b =>
        {
            b.ToTable("alert_triggers");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.AlertRuleId).HasColumnName("alert_rule_id");
            b.Property(x => x.TriggeredAt).HasColumnName("triggered_at").HasDefaultValueSql("now()");
            b.Property(x => x.Payload).HasColumnName("payload").HasColumnType("jsonb");
        });

        modelBuilder.Entity<Alert.Delivery>(b =>
        {
            b.ToTable("alert_deliveries");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.AlertTriggerId).HasColumnName("alert_trigger_id");
            b.Property(x => x.Channel).HasColumnName("channel").HasMaxLength(20);
            b.Property(x => x.Status).HasColumnName("status").HasMaxLength(20);
            b.Property(x => x.DeliveredAt).HasColumnName("delivered_at");
        });

        modelBuilder.Entity<Security.UserActivityLog>(b =>
        {
            b.ToTable("user_activity_logs");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.Action).HasColumnName("action").HasMaxLength(100);
            b.Property(x => x.IpAddress).HasColumnName("ip_address").HasMaxLength(64);
            b.Property(x => x.UserAgent).HasColumnName("user_agent");
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<Security.Event>(b =>
        {
            b.ToTable("security_events");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.EventType).HasColumnName("event_type").HasMaxLength(100);
            b.Property(x => x.Severity).HasColumnName("severity").HasMaxLength(20);
            b.Property(x => x.Metadata).HasColumnName("metadata").HasColumnType("jsonb");
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<Risk.Rule>(b =>
        {
            b.ToTable("risk_rules");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.Scope).HasColumnName("scope").HasMaxLength(50);
            b.Property(x => x.ScopeId).HasColumnName("scope_id");
            b.Property(x => x.RuleType).HasColumnName("rule_type").HasMaxLength(50);
            b.Property(x => x.Threshold).HasColumnName("threshold").HasPrecision(10, 4);
            b.Property(x => x.Action).HasColumnName("action").HasMaxLength(50);
            b.Property(x => x.IsActive).HasColumnName("is_active").HasDefaultValue(true);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<Risk.Violation>(b =>
        {
            b.ToTable("risk_violations");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.RiskRuleId).HasColumnName("risk_rule_id");
            b.Property(x => x.CurrentValue).HasColumnName("current_value").HasPrecision(20, 8);
            b.Property(x => x.ViolatedAt).HasColumnName("violated_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<Risk.Action>(b =>
        {
            b.ToTable("risk_actions");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.ViolationId).HasColumnName("violation_id");
            b.Property(x => x.ExecutedAction).HasColumnName("executed_action").HasMaxLength(50);
            b.Property(x => x.ExecutedAt).HasColumnName("executed_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<Referral.Code>(b =>
        {
            b.ToTable("referral_codes");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.CodeValue).HasColumnName("code").HasMaxLength(50);
            b.HasIndex(x => x.CodeValue).IsUnique();
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<Referral.Activity>(b =>
        {
            b.ToTable("referral_activities");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.ReferrerId).HasColumnName("referrer_id");
            b.Property(x => x.RefereeId).HasColumnName("referee_id");
            b.Property(x => x.ReferralCodeId).HasColumnName("referral_code_id");
            b.Property(x => x.Status).HasColumnName("status").HasMaxLength(20);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<Referral.Reward>(b =>
        {
            b.ToTable("affiliate_rewards");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.ReferrerId).HasColumnName("referrer_id");
            b.Property(x => x.Amount).HasColumnName("amount").HasPrecision(20, 8);
            b.Property(x => x.Status).HasColumnName("status").HasMaxLength(20);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<SubscriptionDomain.Plan>(b =>
        {
            b.ToTable("plans");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.Name).HasColumnName("name").HasMaxLength(50);
            b.Property(x => x.Price).HasColumnName("price").HasPrecision(20, 8);
            b.Property(x => x.BotLimit).HasColumnName("bot_limit");
        });

        modelBuilder.Entity<SubscriptionDomain.Subscription>(b =>
        {
            b.ToTable("subscriptions");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.PlanId).HasColumnName("plan_id");
            b.Property(x => x.Status).HasColumnName("status").HasMaxLength(20);
            b.Property(x => x.StartedAt).HasColumnName("started_at");
            b.Property(x => x.EndedAt).HasColumnName("ended_at");
        });

        modelBuilder.Entity<SubscriptionDomain.Payment>(b =>
        {
            b.ToTable("payments");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.SubscriptionId).HasColumnName("subscription_id");
            b.Property(x => x.Amount).HasColumnName("amount").HasPrecision(20, 8);
            b.Property(x => x.Provider).HasColumnName("provider").HasMaxLength(50);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<SubscriptionDomain.PerformanceFeeConfig>(b =>
        {
            b.ToTable("performance_fee_configs");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.Rate).HasColumnName("rate").HasPrecision(5, 2);
            b.Property(x => x.HighWaterMark).HasColumnName("high_water_mark").HasDefaultValue(true);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<SubscriptionDomain.PerformanceFeeRecord>(b =>
        {
            b.ToTable("performance_fee_records");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.ConfigId).HasColumnName("config_id");
            b.Property(x => x.FollowerId).HasColumnName("follower_id");
            b.Property(x => x.GrossProfit).HasColumnName("gross_profit").HasPrecision(20, 8);
            b.Property(x => x.FeeAmount).HasColumnName("fee_amount").HasPrecision(20, 8);
            b.Property(x => x.Settled).HasColumnName("settled").HasDefaultValue(false);
            b.Property(x => x.CalculatedAt).HasColumnName("calculated_at").HasDefaultValueSql("now()");
        });

        modelBuilder.Entity<Audit.Log>(b =>
        {
            b.ToTable("audit_logs");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedOnAdd();
            b.Property(x => x.UserId).HasColumnName("user_id");
            b.Property(x => x.Action).HasColumnName("action").HasMaxLength(100);
            b.Property(x => x.Metadata).HasColumnName("metadata").HasColumnType("jsonb");
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasDefaultValueSql("now()");
        });

        // ---------- Otp / ExchangeKey (theo entities bạn gửi; không nằm trong schema SQL trước đó) ----------
        modelBuilder.Entity<Otp>(b =>
        {
            b.ToTable("otps");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id");
            b.Property(x => x.Email).HasColumnName("email");
            b.Property(x => x.OtpCode).HasColumnName("otp_code");
            b.Property(x => x.ExpiresAt).HasColumnName("expires_at");
            b.Property(x => x.Type).HasColumnName("type");
            b.Property(x => x.IsUsed).HasColumnName("is_used");
            b.Property(x => x.CreatedAt).HasColumnName("created_at");
        });

        modelBuilder.Entity<ExchangeKey>(b =>
        {
            b.ToTable("exchange_keys");
            b.HasKey(x => x.KeyId);
            b.Property(x => x.KeyId).HasColumnName("key_id");
            b.Property(x => x.UserId).HasColumnName("user_id"); // NOTE: Guid (theo entity hiện tại)
            b.Property(x => x.ExchangeName).HasColumnName("exchange_name");
            b.Property(x => x.ApiKey).HasColumnName("api_key");
            b.Property(x => x.SecretKey).HasColumnName("secret_key");
            b.Property(x => x.Passphrase).HasColumnName("passphrase");
            b.Property(x => x.Label).HasColumnName("label");
            b.Property(x => x.IsActive).HasColumnName("is_active");
            b.Property(x => x.CreatedAt).HasColumnName("created_at");
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at");
            b.Property(x => x.LastVerified).HasColumnName("last_verified");
        });
    }
}
