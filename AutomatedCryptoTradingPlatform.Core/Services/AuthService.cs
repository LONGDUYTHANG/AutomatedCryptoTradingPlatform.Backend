using AutomatedCryptoTradingPlatform.Core.Dtos.Requests;
using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Helpers;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using AutomatedCryptoTradingPlatform.Core.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AutomatedCryptoTradingPlatform.Core.Services;

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly ISocialAccountRepository _socialAccountRepository;
    private readonly ITwoFactorRepository _twoFactorRepository;
    private readonly IConfiguration _configuration;
    private readonly ITwoFactorService _twoFactorService;
    private readonly IExchangeKeyService _exchangeKeyService;
    private readonly IOtpService _otpService;
    private readonly ILogger<AuthService> _logger;

    public AuthService(
        IUserRepository userRepository,
        ISocialAccountRepository socialAccountRepository,
        ITwoFactorRepository twoFactorRepository,
        IConfiguration configuration, 
        ITwoFactorService twoFactorService,
        IExchangeKeyService exchangeKeyService,
        IOtpService otpService,
        ILogger<AuthService> logger)
    {
        _userRepository = userRepository;
        _socialAccountRepository = socialAccountRepository;
        _twoFactorRepository = twoFactorRepository;
        _configuration = configuration;
        _twoFactorService = twoFactorService;
        _exchangeKeyService = exchangeKeyService;
        _otpService = otpService;
        _logger = logger;
    }

    public async Task<AuthResponseDto> RegisterAsync(RegisterDto registerDto)
    {
        var email = registerDto.Email.ToLower();

        // Check if user already exists
        var existingUser = await _userRepository.GetByEmailAsync(email);
        if (existingUser != null)
        {
            throw new Exception("User with this email already exists");
        }

        // Create new user
        var newUser = new Entities.User
        {
            Email = email,
            Username = registerDto.FullName,
            PasswordHash = CryptographyHelper.HashPassword(registerDto.Password),
            Status = "Pending", // Email not verified yet
            Role = "User",
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            Profile = new UserProfile
            {
                DisplayName = registerDto.FullName
            }
        };

        // Save to database
        var userId = await _userRepository.CreateAsync(newUser);
        newUser.Id = userId;

        // Convert to legacy format for response
        var legacyUser = LegacyUser.FromUser(newUser);
        legacyUser.Provider = "Local";
        legacyUser.IsEmailVerified = false;

        // Send email verification OTP
        try
        {
            await _otpService.GenerateAndSendOtpAsync(email, "EmailVerification");
            _logger.LogInformation("Verification email sent to {Email}", email);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send verification email to {Email}", email);
            // Don't fail registration if email sending fails
        }

        return new AuthResponseDto
        {
            UserId = legacyUser.UserId,
            Email = legacyUser.Email,
            FullName = legacyUser.FullName,
            TwoFactorEnabled = legacyUser.TwoFactorEnabled
        };
    }

    public async Task<AuthResponseDto> LoginAsync(LoginDto loginDto)
    {
        var email = loginDto.Email.ToLower();

        // Get user from database with all relations
        var user = await GetUserByEmailAsync(email);
        if (user == null)
        {
            throw new Exception("Invalid email or password");
        }

        // Verify password
        if (string.IsNullOrEmpty(user.PasswordHash) || !CryptographyHelper.VerifyPassword(loginDto.Password, user.PasswordHash))
        {
            throw new Exception("Invalid email or password");
        }

        // Check if email is verified (only for local accounts)
        if (user.Provider == "Local" && !user.IsEmailVerified)
        {
            // Resend OTP if needed
            try
            {
                await _otpService.GenerateAndSendOtpAsync(email, "EmailVerification");
                throw new Exception("Please verify your email before logging in. A new verification code has been sent to your email.");
            }
            catch (Exception ex) when (ex.Message.Contains("verify your email"))
            {
                throw; // Rethrow our message
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to resend verification email to {Email}", email);
                throw new Exception("Please verify your email before logging in. Check your email for the verification code.");
            }
        }

        // Check if user is active
        if (!user.IsActive)
        {
            throw new Exception("Account is deactivated. Please contact support.");
        }

        // Check if 2FA is enabled - return partial token for verification
        if (user.TwoFactorEnabled)
        {
            var partialToken = await GenerateJwtTokenAsync(user, partialFor2FA: true);
            return new AuthResponseDto
            {
                UserId = user.UserId,
                Email = user.Email,
                FullName = user.FullName,
                TwoFactorEnabled = true,
                Require2FA = true,
                Token = partialToken // Partial token with 2fa_pending claim
            };
        }

        // Generate full access token for users without 2FA
        var token = await GenerateJwtTokenAsync(user);
        return new AuthResponseDto
        {
            UserId = user.UserId,
            Email = user.Email,
            FullName = user.FullName,
            TwoFactorEnabled = user.TwoFactorEnabled,
            Require2FA = false,
            Token = token
        };
    }

    public async Task<string> GenerateJwtTokenAsync(LegacyUser user, bool isRefresh = false, bool partialFor2FA = false)
    {
        var jwtSettings = _configuration.GetSection("JwtSettings");
        var secretKey = jwtSettings["SecretKey"] ?? throw new Exception("JWT SecretKey not configured");
        var issuer = jwtSettings["Issuer"] ?? "AutomatedCryptoTradingPlatform";
        var audience = jwtSettings["Audience"] ?? "AutomatedCryptoTradingPlatform";
        var expiryMinutes = int.Parse(jwtSettings["ExpiryMinutes"] ?? "60");

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claimsList = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserId.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim("fullName", user.FullName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        // Add 2FA pending claim for partial tokens
        if (partialFor2FA)
        {
            claimsList.Add(new Claim("2fa_pending", "true"));
        }

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claimsList,
            expires: DateTime.UtcNow.AddMinutes(partialFor2FA ? 5 : expiryMinutes), // Partial tokens expire in 5 minutes
            signingCredentials: credentials
        );

        return await Task.FromResult(new JwtSecurityTokenHandler().WriteToken(token));
    }

    public async Task<LegacyUser?> GetUserByEmailAsync(string email)
    {
        var user = await _userRepository.GetByEmailWithAllRelationsAsync(email.ToLower());
        if (user == null) return null;

        return LegacyUser.FromUser(user);
    }

    public async Task<LegacyUser?> GetUserByProviderAsync(string provider, string providerId)
    {
        var socialAccount = await _socialAccountRepository.GetByProviderAsync(provider, providerId);
        if (socialAccount == null) return null;

        var user = await _userRepository.GetUserWithAllRelationsAsync(socialAccount.UserId);
        if (user == null) return null;

        var legacyUser = LegacyUser.FromUser(user);
        legacyUser.Provider = provider;
        legacyUser.ProviderId = providerId;
        
        return legacyUser;
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
            var newUser = new Entities.User
            {
                Email = externalLoginDto.Email?.ToLower() ?? $"{externalLoginDto.ProviderId}@{externalLoginDto.Provider.ToLower()}.com",
                Username = externalLoginDto.FullName ?? "User",
                PasswordHash = null, // OAuth users don't have password
                Status = "Active",
                Role = "User",
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow,
                Profile = new UserProfile
                {
                    DisplayName = externalLoginDto.FullName ?? "User"
                }
            };

            // Save to database
            var userId = await _userRepository.CreateAsync(newUser);
            newUser.Id = userId;

            // Create social account link
            var socialAccount = new SocialAccount
            {
                UserId = userId,
                Provider = externalLoginDto.Provider,
                ProviderUserId = externalLoginDto.ProviderId!,
                CreatedAt = DateTime.UtcNow
            };
            await _socialAccountRepository.CreateAsync(socialAccount);

            // Convert to legacy format for response
            user = LegacyUser.FromUser(newUser);
            user.Provider = externalLoginDto.Provider;
            user.ProviderId = externalLoginDto.ProviderId;
        }
        else
        {
            // User exists - update last login
            var dbUser = await _userRepository.GetByEmailAsync(user.Email);
            if (dbUser != null)
            {
                dbUser.UpdatedAt = DateTime.UtcNow;
                await _userRepository.UpdateAsync(dbUser);
            }
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

        // Get user from database
        var user = await GetUserByEmailAsync(email);
        if (user == null)
        {
            throw new Exception("User not found");
        }

        // Convert to database user and update password
        var dbUser = await _userRepository.GetByEmailAsync(email);
        if (dbUser == null)
        {
            throw new Exception("User not found");
        }

        dbUser.PasswordHash = CryptographyHelper.HashPassword(resetPasswordDto.NewPassword);
        dbUser.UpdatedAt = DateTime.UtcNow;

        await _userRepository.UpdateAsync(dbUser);
    }

    public async Task ChangePasswordAsync(Guid userId, ChangePasswordDto changePasswordDto)
    {
        // Get user from database
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            throw new Exception("User not found");
        }

        // Verify current password
        if (string.IsNullOrEmpty(user.PasswordHash) || !CryptographyHelper.VerifyPassword(changePasswordDto.CurrentPassword, user.PasswordHash))
        {
            throw new Exception("Current password is incorrect");
        }

        // Verify OTP
        var isOtpValid = await _otpService.VerifyOtpAsync(user.Email, changePasswordDto.OtpCode, "ChangePassword");
        if (!isOtpValid)
        {
            throw new Exception("Invalid or expired OTP code");
        }

        // Get database user and update password
        var dbUser = await _userRepository.GetByEmailAsync(user.Email);
        if (dbUser == null)
        {
            throw new Exception("User not found");
        }

        dbUser.PasswordHash = CryptographyHelper.HashPassword(changePasswordDto.NewPassword);
        dbUser.UpdatedAt = DateTime.UtcNow;

        await _userRepository.UpdateAsync(dbUser);
        
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

        // Convert Guid to long ID
        var bytes = userId.ToByteArray();
        var longId = BitConverter.ToInt64(bytes, 0);

        // Check if 2FA record exists
        var existing2FA = await _twoFactorRepository.GetByUserIdAsync(longId);
        if (existing2FA != null)
        {
            // Update existing
            existing2FA.Secret = twoFactorData.Secret;
            existing2FA.Enabled = false; // Not enabled until verified
            await _twoFactorRepository.UpdateAsync(existing2FA);
        }
        else
        {
            // Create new 2FA record
            var twoFactor = new TwoFactorAuth
            {
                UserId = longId,
                Secret = twoFactorData.Secret,
                Enabled = false
            };
            await _twoFactorRepository.CreateAsync(twoFactor);
        }

        return twoFactorData;
    }

    public async Task VerifyAndActivateTwoFactorAsync(Guid userId, string code)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            throw new Exception("User not found");
        }

        // Convert Guid to long ID
        var bytes = userId.ToByteArray();
        var longId = BitConverter.ToInt64(bytes, 0);

        // Get 2FA record
        var twoFactor = await _twoFactorRepository.GetByUserIdAsync(longId);
        if (twoFactor == null || string.IsNullOrWhiteSpace(twoFactor.Secret))
        {
            throw new Exception("2FA secret not generated. Please request to enable 2FA first.");
        }

        if (twoFactor.Enabled)
        {
            throw new Exception("2FA is already enabled");
        }

        // Verify the code
        if (!_twoFactorService.VerifyTwoFactorCode(twoFactor.Secret, code))
        {
            throw new Exception("Invalid 2FA code");
        }

        // Activate 2FA
        twoFactor.Enabled = true;
        await _twoFactorRepository.UpdateAsync(twoFactor);
    }

    public async Task DisableTwoFactorAsync(Guid userId, string password)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null)
        {
            throw new Exception("User not found");
        }

        // Verify password
        if (string.IsNullOrEmpty(user.PasswordHash) || !CryptographyHelper.VerifyPassword(password, user.PasswordHash))
        {
            throw new Exception("Invalid password");
        }

        // Convert Guid to long ID
        var bytes = userId.ToByteArray();
        var longId = BitConverter.ToInt64(bytes, 0);

        // Get and disable 2FA
        var twoFactor = await _twoFactorRepository.GetByUserIdAsync(longId);
        if (twoFactor != null)
        {
            twoFactor.Enabled = false;
            twoFactor.Secret = string.Empty;
            await _twoFactorRepository.UpdateAsync(twoFactor);
        }
    }

    public async Task<LegacyUser?> GetUserByIdAsync(Guid userId)
    {
        // Convert Guid to long (take last 8 bytes)
        var bytes = userId.ToByteArray();
        var longId = BitConverter.ToInt64(bytes, 0);
        
        var dbUser = await _userRepository.GetUserWithAllRelationsAsync(longId);
        if (dbUser == null) return null;

        return LegacyUser.FromUser(dbUser);
    }

    public async Task<bool> Verify2FAAsync(Guid userId, string twoFactorCode)
    {
        var user = await GetUserByIdAsync(userId);
        if (user == null || !user.TwoFactorEnabled)
        {
            return false;
        }

        return _twoFactorService.VerifyTwoFactorCode(user.TwoFactorSecret ?? string.Empty, twoFactorCode);
    }

    public async Task SendVerificationEmailAsync(string email)
    {
        // Check if user exists
        var user = await GetUserByEmailAsync(email.ToLower());
        if (user == null)
        {
            throw new Exception("User not found");
        }

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
        var dbUser = await _userRepository.GetByEmailAsync(email.ToLower());
        if (dbUser == null)
        {
            throw new Exception("User not found");
        }

        dbUser.Status = "Active"; // Change from Pending to Active
        dbUser.UpdatedAt = DateTime.UtcNow;
        await _userRepository.UpdateAsync(dbUser);
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
        if (existingUser != null)
        {
            return new AuthResponseDto
            {
                UserId = existingUser.UserId,
                Email = existingUser.Email,
                FullName = existingUser.FullName,
                TwoFactorEnabled = existingUser.TwoFactorEnabled,
                Require2FA = false
            };
        }

        // Create new user with Binance account
        var newUser = new Entities.User
        {
            Email = $"binance_{binanceUid}@exchange.local",
            Username = $"Binance User {binanceUid}",
            PasswordHash = null,
            Status = "Active",
            Role = "User",
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            Profile = new UserProfile
            {
                DisplayName = $"Binance User {binanceUid}"
            }
        };

        var userId = await _userRepository.CreateAsync(newUser);
        newUser.Id = userId;

        // Create social account link for Binance
        var socialAccount = new SocialAccount
        {
            UserId = userId,
            Provider = "Binance",
            ProviderUserId = binanceUid,
            CreatedAt = DateTime.UtcNow
        };
        await _socialAccountRepository.CreateAsync(socialAccount);

        var legacyUser = LegacyUser.FromUser(newUser);
        legacyUser.Provider = "Binance";
        legacyUser.ProviderId = binanceUid;

        return new AuthResponseDto
        {
            UserId = legacyUser.UserId,
            Email = legacyUser.Email,
            FullName = legacyUser.FullName,
            TwoFactorEnabled = false,
            Require2FA = false
        };
    }

    public async Task<AuthResponseDto> OkxLoginAsync(OkxLoginDto dto)
    {
        // Verify API key and get account info from OKX
        var accountInfo = await _exchangeKeyService.GetAccountInfoAsync(
            "OKX",
            dto.ApiKey,
            dto.SecretKey,
            false,
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
        if (existingUser != null)
        {
            return new AuthResponseDto
            {
                UserId = existingUser.UserId,
                Email = existingUser.Email,
                FullName = existingUser.FullName,
                TwoFactorEnabled = existingUser.TwoFactorEnabled,
                Require2FA = false
            };
        }

        // Create new user with OKX account
        var newUser = new Entities.User
        {
            Email = $"okx_{okxUid}@exchange.local",
            Username = $"OKX User {okxUid}",
            PasswordHash = null,
            Status = "Active",
            Role = "User",
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow,
            Profile = new UserProfile
            {
                DisplayName = $"OKX User {okxUid}"
            }
        };

        var userId = await _userRepository.CreateAsync(newUser);
        newUser.Id = userId;

        // Create social account link for OKX
        var socialAccount = new SocialAccount
        {
            UserId = userId,
            Provider = "OKX",
            ProviderUserId = okxUid,
            CreatedAt = DateTime.UtcNow
        };
        await _socialAccountRepository.CreateAsync(socialAccount);

        var legacyUser = LegacyUser.FromUser(newUser);
        legacyUser.Provider = "OKX";
        legacyUser.ProviderId = okxUid;

        return new AuthResponseDto
        {
            UserId = legacyUser.UserId,
            Email = legacyUser.Email,
            FullName = legacyUser.FullName,
            TwoFactorEnabled = false,
            Require2FA = false
        };
    }
}
