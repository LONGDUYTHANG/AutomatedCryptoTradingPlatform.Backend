using AutomatedCryptoTradingPlatform.Core.Dtos.Requests;
using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Helpers;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AutomatedCryptoTradingPlatform.Core.Services;

public class AuthService : IAuthService
{
    // In-memory storage (temporary, will be replaced with database later)
    private static readonly Dictionary<string, User> _users = new();
    private readonly IConfiguration _configuration;
    private readonly ITwoFactorService _twoFactorService;
    private readonly IExchangeKeyService _exchangeKeyService;
    private readonly IOtpService _otpService;

    public AuthService(
        IConfiguration configuration, 
        ITwoFactorService twoFactorService,
        IExchangeKeyService exchangeKeyService,
        IOtpService otpService)
    {
        _configuration = configuration;
        _twoFactorService = twoFactorService;
        _exchangeKeyService = exchangeKeyService;
        _otpService = otpService;
    }

    public async Task<AuthResponseDto> RegisterAsync(RegisterDto registerDto)
    {
        // Check if user already exists
        if (_users.ContainsKey(registerDto.Email.ToLower()))
        {
            throw new Exception("User with this email already exists");
        }

        // Create new user
        var user = new User
        {
            UserId = Guid.NewGuid(),
            Email = registerDto.Email.ToLower(),
            PasswordHash = CryptographyHelper.HashPassword(registerDto.Password),
            FullName = registerDto.FullName,
            Provider = "Local",
            IsEmailVerified = false, // Email not verified yet
            CreatedAt = DateTime.UtcNow
        };

        // Store user in memory
        _users[user.Email] = user;

        return await Task.FromResult(new AuthResponseDto
        {
            UserId = user.UserId,
            Email = user.Email,
            FullName = user.FullName,
            TwoFactorEnabled = user.TwoFactorEnabled
        });
    }

    public async Task<AuthResponseDto> LoginAsync(LoginDto loginDto)
    {
        var email = loginDto.Email.ToLower();

        // Check if user exists
        if (!_users.ContainsKey(email))
        {
            throw new Exception("Invalid email or password");
        }

        var user = _users[email];

        // Verify password
        if (!CryptographyHelper.VerifyPassword(loginDto.Password, user.PasswordHash))
        {
            throw new Exception("Invalid email or password");
        }

        // Check if email is verified (only for local accounts)
        if (user.Provider == "Local" && !user.IsEmailVerified)
        {
            throw new Exception("Please verify your email before logging in");
        }

        // Check if user is active
        if (!user.IsActive)
        {
            throw new Exception("Account is deactivated");
        }

        // Check if 2FA is enabled
        if (user.TwoFactorEnabled)
        {
            // If 2FA code is not provided
            if (string.IsNullOrWhiteSpace(loginDto.TwoFactorCode))
            {
                return await Task.FromResult(new AuthResponseDto
                {
                    UserId = user.UserId,
                    Email = user.Email,
                    FullName = user.FullName,
                    TwoFactorEnabled = true,
                    Require2FA = true
                });
            }

            // Verify 2FA code
            if (!_twoFactorService.VerifyTwoFactorCode(user.TwoFactorSecret ?? string.Empty, loginDto.TwoFactorCode))
            {
                throw new Exception("Invalid 2FA code");
            }
        }

        return await Task.FromResult(new AuthResponseDto
        {
            UserId = user.UserId,
            Email = user.Email,
            FullName = user.FullName,
            TwoFactorEnabled = user.TwoFactorEnabled,
            Require2FA = false
        });
    }

    public async Task<string> GenerateJwtTokenAsync(User user)
    {
        var jwtSettings = _configuration.GetSection("JwtSettings");
        var secretKey = jwtSettings["SecretKey"] ?? throw new Exception("JWT SecretKey not configured");
        var issuer = jwtSettings["Issuer"] ?? "AutomatedCryptoTradingPlatform";
        var audience = jwtSettings["Audience"] ?? "AutomatedCryptoTradingPlatform";
        var expiryMinutes = int.Parse(jwtSettings["ExpiryMinutes"] ?? "60");

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim("fullName", user.FullName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(expiryMinutes),
            signingCredentials: credentials
        );

        return await Task.FromResult(new JwtSecurityTokenHandler().WriteToken(token));
    }

    public async Task<User?> GetUserByEmailAsync(string email)
    {
        _users.TryGetValue(email.ToLower(), out var user);
        return await Task.FromResult(user);
    }

    public async Task<User?> GetUserByProviderAsync(string provider, string providerId)
    {
        var user = _users.Values.FirstOrDefault(u => 
            u.Provider == provider && u.ProviderId == providerId);
        return await Task.FromResult(user);
    }

    public async Task<AuthResponseDto> ExternalLoginAsync(ExternalLoginDto externalLoginDto)
    {
        // Check if user exists by provider ID
        var user = await GetUserByProviderAsync(externalLoginDto.Provider, externalLoginDto.ProviderId!);

        if (user == null)
        {
            // Check if email already exists with different provider
            if (!string.IsNullOrEmpty(externalLoginDto.Email))
            {
                var existingUser = await GetUserByEmailAsync(externalLoginDto.Email);
                if (existingUser != null)
                {
                    throw new Exception($"Email already registered with {existingUser.Provider} provider");
                }
            }

            // Create new user from OAuth provider
            user = new User
            {
                UserId = Guid.NewGuid(),
                Email = externalLoginDto.Email?.ToLower() ?? $"{externalLoginDto.ProviderId}@{externalLoginDto.Provider.ToLower()}.com",
                FullName = externalLoginDto.FullName ?? "User",
                Provider = externalLoginDto.Provider,
                ProviderId = externalLoginDto.ProviderId,
                PasswordHash = string.Empty, // OAuth users don't have password
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            _users[user.Email] = user;
        }
        else
        {
            // Update last login info
            user.UpdatedAt = DateTime.UtcNow;
            _users[user.Email] = user;
        }

        return new AuthResponseDto
        {
            UserId = user.UserId,
            Email = user.Email,
            FullName = user.FullName,
            TwoFactorEnabled = user.TwoFactorEnabled,
            Require2FA = user.TwoFactorEnabled
        };
    }

    public async Task ResetPasswordAsync(ResetPasswordDto resetPasswordDto)
    {
        var email = resetPasswordDto.Email.ToLower();

        // Check if user exists
        if (!_users.ContainsKey(email))
        {
            throw new Exception("User not found");
        }

        var user = _users[email];

        // Update password
        user.PasswordHash = CryptographyHelper.HashPassword(resetPasswordDto.NewPassword);
        user.UpdatedAt = DateTime.UtcNow;

        _users[email] = user;

        await Task.CompletedTask;
    }

    public async Task ChangePasswordAsync(Guid userId, ChangePasswordDto changePasswordDto)
    {
        // Find user by ID
        var user = _users.Values.FirstOrDefault(u => u.UserId == userId);

        if (user == null)
        {
            throw new Exception("User not found");
        }

        // Verify current password
        if (!CryptographyHelper.VerifyPassword(changePasswordDto.CurrentPassword, user.PasswordHash))
        {
            throw new Exception("Current password is incorrect");
        }

        // Verify OTP
        var isOtpValid = await _otpService.VerifyOtpAsync(user.Email, changePasswordDto.OtpCode, "ChangePassword");
        if (!isOtpValid)
        {
            throw new Exception("Invalid or expired OTP code");
        }

        // Update password
        user.PasswordHash = CryptographyHelper.HashPassword(changePasswordDto.NewPassword);
        user.UpdatedAt = DateTime.UtcNow;

        _users[user.Email] = user;
        
        // Invalidate OTP after successful password change
        await _otpService.InvalidateOtpAsync(user.Email, "ChangePassword");
    }

    public async Task<Enable2FaResponseDto> EnableTwoFactorAsync(Guid userId)
    {
        var user = await GetUserByIdAsync(userId);

        if (user == null)
        {
            throw new Exception("User not found");
        }

        if (user.TwoFactorEnabled)
        {
            throw new Exception("2FA is already enabled");
        }

        // Generate new 2FA secret
        var twoFactorData = _twoFactorService.GenerateTwoFactorSecret(user.Email);

        // Store the secret temporarily (not activated yet until user verifies)
        user.TwoFactorSecret = twoFactorData.Secret;
        user.UpdatedAt = DateTime.UtcNow;
        _users[user.Email] = user;

        return twoFactorData;
    }

    public async Task VerifyAndActivateTwoFactorAsync(Guid userId, string code)
    {
        var user = await GetUserByIdAsync(userId);

        if (user == null)
        {
            throw new Exception("User not found");
        }

        if (user.TwoFactorEnabled)
        {
            throw new Exception("2FA is already enabled");
        }

        if (string.IsNullOrWhiteSpace(user.TwoFactorSecret))
        {
            throw new Exception("2FA secret not generated. Please request to enable 2FA first.");
        }

        // Verify the code
        if (!_twoFactorService.VerifyTwoFactorCode(user.TwoFactorSecret, code))
        {
            throw new Exception("Invalid 2FA code");
        }

        // Activate 2FA
        user.TwoFactorEnabled = true;
        user.UpdatedAt = DateTime.UtcNow;
        _users[user.Email] = user;

        await Task.CompletedTask;
    }

    public async Task DisableTwoFactorAsync(Guid userId, string password)
    {
        var user = await GetUserByIdAsync(userId);

        if (user == null)
        {
            throw new Exception("User not found");
        }

        if (!user.TwoFactorEnabled)
        {
            throw new Exception("2FA is not enabled");
        }

        // Verify password for security
        if (!CryptographyHelper.VerifyPassword(password, user.PasswordHash))
        {
            throw new Exception("Invalid password");
        }

        // Disable 2FA
        user.TwoFactorEnabled = false;
        user.TwoFactorSecret = null;
        user.UpdatedAt = DateTime.UtcNow;
        _users[user.Email] = user;

        await Task.CompletedTask;
    }

    public async Task<User?> GetUserByIdAsync(Guid userId)
    {
        var user = _users.Values.FirstOrDefault(u => u.UserId == userId);
        return await Task.FromResult(user);
    }

    public async Task SendVerificationEmailAsync(string email)
    {
        // Check if user exists
        if (!_users.ContainsKey(email.ToLower()))
        {
            throw new Exception("User not found");
        }

        var user = _users[email.ToLower()];

        // Check if already verified
        if (user.IsEmailVerified)
        {
            throw new Exception("Email is already verified");
        }

        // Generate and send OTP
        await _otpService.GenerateAndSendOtpAsync(email, "EmailVerification");
    }

    public async Task VerifyEmailAsync(string email, string otpCode)
    {
        // Verify OTP
        var isValid = await _otpService.VerifyOtpAsync(email, otpCode, "EmailVerification");
        
        if (!isValid)
        {
            throw new Exception("Invalid or expired OTP code");
        }

        // Update user's email verification status
        if (!_users.ContainsKey(email.ToLower()))
        {
            throw new Exception("User not found");
        }

        var user = _users[email.ToLower()];
        user.IsEmailVerified = true;
        user.UpdatedAt = DateTime.UtcNow;
        _users[user.Email] = user;

        await Task.CompletedTask;
    }

    public async Task<AuthResponseDto> BinanceLoginAsync(BinanceLoginDto dto)
    {
        // Verify API key and get account info from Binance
        var accountInfo = await _exchangeKeyService.GetAccountInfoAsync(
            "Binance",
            dto.ApiKey,
            dto.SecretKey,
            dto.IsTestnet
        );

        if (accountInfo == null || !accountInfo.ContainsKey("uid"))
        {
            throw new Exception("Failed to verify Binance API key. Please check your credentials.");
        }

        var binanceUid = accountInfo["uid"]?.ToString();
        if (string.IsNullOrEmpty(binanceUid))
        {
            throw new Exception("Unable to retrieve Binance UID from account info");
        }

        // Check if user already exists with this Binance account
        var existingUser = await GetUserByProviderAsync("Binance", binanceUid);

        User user;
        if (existingUser == null)
        {
            // Create new user with Binance account
            user = new User
            {
                UserId = Guid.NewGuid(),
                Email = $"binance_{binanceUid}@exchange.local", // Pseudo email
                PasswordHash = string.Empty, // External login, no password
                FullName = $"Binance User {binanceUid}",
                Provider = "Binance",
                ProviderId = binanceUid,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _users[user.Email] = user;
        }
        else
        {
            user = existingUser;
        }

        return new AuthResponseDto
        {
            UserId = user.UserId,
            Email = user.Email,
            FullName = user.FullName,
            TwoFactorEnabled = user.TwoFactorEnabled,
            Require2FA = false // Skip 2FA for exchange login (API key is already strong auth)
        };
    }

    public async Task<AuthResponseDto> OkxLoginAsync(OkxLoginDto dto)
    {
        // Verify API key and get account info from OKX
        var accountInfo = await _exchangeKeyService.GetAccountInfoAsync(
            "OKX",
            dto.ApiKey,
            dto.SecretKey,
            false, // OKX doesn't have testnet in same way
            dto.Passphrase
        );

        if (accountInfo == null || !accountInfo.ContainsKey("uid"))
        {
            throw new Exception("Failed to verify OKX API key. Please check your credentials.");
        }

        var okxUid = accountInfo["uid"]?.ToString();
        if (string.IsNullOrEmpty(okxUid))
        {
            throw new Exception("Unable to retrieve OKX UID from account info");
        }

        // Check if user already exists with this OKX account
        var existingUser = await GetUserByProviderAsync("OKX", okxUid);

        User user;
        if (existingUser == null)
        {
            // Create new user with OKX account
            user = new User
            {
                UserId = Guid.NewGuid(),
                Email = $"okx_{okxUid}@exchange.local", // Pseudo email
                PasswordHash = string.Empty, // External login, no password
                FullName = $"OKX User {okxUid}",
                Provider = "OKX",
                ProviderId = okxUid,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            _users[user.Email] = user;
        }
        else
        {
            user = existingUser;
        }

        return new AuthResponseDto
        {
            UserId = user.UserId,
            Email = user.Email,
            FullName = user.FullName,
            TwoFactorEnabled = user.TwoFactorEnabled,
            Require2FA = false // Skip 2FA for exchange login (API key is already strong auth)
        };
    }
}
