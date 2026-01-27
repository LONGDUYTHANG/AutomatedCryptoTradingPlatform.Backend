using AutomatedCryptoTradingPlatform.API.Middlewares;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Repositories;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using AutomatedCryptoTradingPlatform.Core.Services;
using AutomatedCryptoTradingPlatform.Infrastructure.Repositories;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Thêm services
builder.Services.AddControllers();

//Cấu hình JSON serializer, xóa naming policy mặc định, không tự convert PascalCase => SnakeCase
builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.PropertyNamingPolicy = null;
});

// Cấu hình swagger UI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Cấu hình Redis
var redisConnectionString = builder.Configuration.GetSection("RedisSettings")["ConnectionString"] 
    ?? throw new Exception("Redis ConnectionString not configured");

builder.Services.AddSingleton<IConnectionMultiplexer>(sp =>
{
    var configuration = ConfigurationOptions.Parse(redisConnectionString, true);
    configuration.AbortOnConnectFail = false; // Không abort khi không kết nối được Redis
    configuration.ConnectTimeout = 5000; // 5 seconds timeout
    configuration.SyncTimeout = 5000;
    return ConnectionMultiplexer.Connect(configuration);
});

builder.Services.AddStackExchangeRedisCache(options =>
{
    options.Configuration = redisConnectionString;
    options.InstanceName = builder.Configuration.GetSection("RedisSettings")["InstanceName"] ?? "CryptoTradingPlatform:";
});

//Cấu hình DI
builder.Services.AddScoped(typeof(IBaseRepository<>), typeof(BaseRepository<>));
builder.Services.AddScoped(typeof(IBaseService<>), typeof(BaseService<>));
builder.Services.AddScoped<IRedisService, RedisService>();
builder.Services.AddScoped<ISessionRepository, SessionRepository>();
builder.Services.AddScoped<ISessionService, SessionService>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IEmailService, EmailService>();
builder.Services.AddScoped<IOtpService, OtpService>();
builder.Services.AddScoped<IOAuthService, OAuthService>();
builder.Services.AddScoped<ITwoFactorService, TwoFactorService>();
builder.Services.AddScoped<IProviderVerificationService, ProviderVerificationService>();
builder.Services.AddScoped<IWalletAuthService, WalletAuthService>();

// Database Repositories với connection string từ configuration
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? throw new Exception("Database ConnectionString not configured");

builder.Services.AddScoped<AutomatedCryptoTradingPlatform.Core.Interfaces.IUserRepository>(sp => 
    new AutomatedCryptoTradingPlatform.Infrastructure.Repositories.UserRepository(connectionString));
builder.Services.AddScoped<AutomatedCryptoTradingPlatform.Core.Interfaces.ISocialAccountRepository>(sp => 
    new SocialAccountRepository(connectionString));
builder.Services.AddScoped<AutomatedCryptoTradingPlatform.Core.Interfaces.IWalletRepository>(sp => 
    new WalletRepository(connectionString));
builder.Services.AddScoped<AutomatedCryptoTradingPlatform.Core.Interfaces.ITwoFactorRepository>(sp => 
    new TwoFactorRepository(connectionString));

// Exchange Repositories
builder.Services.AddScoped<AutomatedCryptoTradingPlatform.Core.Interfaces.IExchangeRepository>(sp => 
    new ExchangeRepository(connectionString));
builder.Services.AddScoped<AutomatedCryptoTradingPlatform.Core.Interfaces.IExchangeAccountRepository>(sp => 
    new ExchangeAccountRepository(connectionString));
builder.Services.AddScoped<AutomatedCryptoTradingPlatform.Core.Interfaces.IExchangeApiKeyRepository>(sp => 
    new ExchangeApiKeyRepository(connectionString));

// ExchangeKeyService - inject repositories
builder.Services.AddScoped<IExchangeKeyService>(sp =>
{
    var config = sp.GetRequiredService<IConfiguration>();
    var httpClient = sp.GetRequiredService<IHttpClientFactory>().CreateClient();
    var exchangeRepo = sp.GetRequiredService<AutomatedCryptoTradingPlatform.Core.Interfaces.IExchangeRepository>();
    var accountRepo = sp.GetRequiredService<AutomatedCryptoTradingPlatform.Core.Interfaces.IExchangeAccountRepository>();
    var apiKeyRepo = sp.GetRequiredService<AutomatedCryptoTradingPlatform.Core.Interfaces.IExchangeApiKeyRepository>();
    
    return new ExchangeKeyService(config, httpClient, exchangeRepo, accountRepo, apiKeyRepo);
});


// Thêm HttpClient factory
builder.Services.AddHttpClient();

// Thêm HttpClient cho ProviderVerificationService (OAuth token verification)
builder.Services.AddHttpClient<IProviderVerificationService, ProviderVerificationService>();

// Cấu hình JWT Authentication
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"] ?? throw new Exception("JWT SecretKey not configured");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey))
    };

    // Read token from Cookie instead of Authorization header
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            // Check if token exists in cookie
            if (context.Request.Cookies.ContainsKey("accessToken"))
            {
                context.Token = context.Request.Cookies["accessToken"];
            }
            return Task.CompletedTask;
        }
    };
});

// Cấu hình CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.WithOrigins(
                "http://localhost:3000",
                "http://localhost:5173",
                "http://localhost:5000"  // Add API itself for testing
              )
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// Dapper config 
Dapper.DefaultTypeMap.MatchNamesWithUnderscores = true;

var app = builder.Build();

// Đăng kí Global Exception Middleware
app.UseMiddleware<GlobalExceptionMiddleware>();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors("AllowAll");

app.UseAuthentication();

// Add 2FA Authorization Middleware - MUST be after UseAuthentication()
app.UseTwoFactorAuthorization();

app.UseAuthorization();

app.MapControllers();

app.Run();
