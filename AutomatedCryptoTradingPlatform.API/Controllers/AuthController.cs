using AutomatedCryptoTradingPlatform.Core.Dtos.Requests;
using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AutomatedCryptoTradingPlatform.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly IOtpService _otpService;
    private readonly IOAuthService _oauthService;
    private readonly IWalletAuthService _walletAuthService;

    public AuthController(
        IAuthService authService, 
        IOtpService otpService,
        IOAuthService oauthService,
        IWalletAuthService walletAuthService)
    {
        _authService = authService;
        _otpService = otpService;
        _oauthService = oauthService;
        _walletAuthService = walletAuthService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
    {
        try
        {
            var result = await _authService.RegisterAsync(registerDto);

            // Send verification email
            await _authService.SendVerificationEmailAsync(registerDto.Email);

            return Ok(new BaseResponse<AuthResponseDto>
            {
                Success = true,
                Message = "User registered successfully. Please check your email to verify your account.",
                Data = result,
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
    {
        try
        {
            var result = await _authService.LoginAsync(loginDto);

            // Set HttpOnly Cookie with token from AuthResponseDto
            if (!string.IsNullOrEmpty(result.Token))
            {
                HttpContext.Response.Cookies.Append("accessToken", result.Token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true, // Only works with HTTPS
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddMinutes(result.Require2FA ? 5 : 60) // Partial tokens expire in 5 min
                });
            }

            return Ok(new BaseResponse<AuthResponseDto>
            {
                Success = true,
                Message = result.Require2FA ? "2FA code required. Please verify using the code from your authenticator app." : "Login successful",
                Data = result,
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return Unauthorized(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 401
            });
        }
    }

    [HttpPost("verify-2fa")]
    public async Task<IActionResult> Verify2FA([FromBody] Verify2FaDto verify2FaDto)
    {
        try
        {
            // Get userId from claims (user must be partially authenticated after login)
            var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            
            if (string.IsNullOrEmpty(userIdClaim))
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "Please login first before verifying 2FA",
                    StatusCode = 401
                });
            }

            // Check if this is a partial token (2FA pending)
            var twoFactorPending = User.FindFirst("2fa_pending")?.Value;
            if (twoFactorPending != "true")
            {
                return BadRequest(new BaseResponse<object>
                {
                    Success = false,
                    Message = "2FA verification not required for this session",
                    StatusCode = 400
                });
            }

            if (!Guid.TryParse(userIdClaim, out var userId))
            {
                return BadRequest(new BaseResponse<object>
                {
                    Success = false,
                    Message = "Invalid user ID",
                    StatusCode = 400
                });
            }

            // Verify 2FA code
            var isValid = await _authService.Verify2FAAsync(userId, verify2FaDto.Code);

            if (!isValid)
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "Invalid 2FA code",
                    StatusCode = 401
                });
            }

            // Get user info
            var user = await _authService.GetUserByIdAsync(userId);
            if (user == null)
            {
                return NotFound(new BaseResponse<object>
                {
                    Success = false,
                    Message = "User not found",
                    StatusCode = 404
                });
            }

            // Generate new JWT token with full access (2FA verified)
            var token = await _authService.GenerateJwtTokenAsync(user);

            // Set HttpOnly Cookie
            HttpContext.Response.Cookies.Append("accessToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddMinutes(60)
            });

            return Ok(new BaseResponse<AuthResponseDto>
            {
                Success = true,
                Message = "2FA verification successful",
                Data = new AuthResponseDto
                {
                    UserId = user.UserId,
                    Email = user.Email,
                    FullName = user.FullName,
                    TwoFactorEnabled = user.TwoFactorEnabled,
                    Require2FA = false
                },
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        // Clear the cookie
        HttpContext.Response.Cookies.Delete("accessToken");

        return Ok(new BaseResponse<object>
        {
            Success = true,
            Message = "Logged out successfully",
            StatusCode = 200
        });
    }

    [Authorize]
    [HttpGet("me")]
    public IActionResult GetCurrentUser()
    {
        var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
        var fullName = User.FindFirst("fullName")?.Value;

        return Ok(new BaseResponse<object>
        {
            Success = true,
            Message = "User retrieved successfully",
            Data = new
            {
                UserId = userId,
                Email = email,
                FullName = fullName
            },
            StatusCode = 200
        });
    }

    #region Email Verification

    /// <summary>
    /// Verify email with OTP code
    /// </summary>
    [HttpPost("verify-email")]
    public async Task<IActionResult> VerifyEmail([FromBody] VerifyEmailDto verifyEmailDto)
    {
        try
        {
            await _authService.VerifyEmailAsync(verifyEmailDto.Email, verifyEmailDto.OtpCode);

            return Ok(new BaseResponse<object>
            {
                Success = true,
                Message = "Email verified successfully. You can now login.",
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    /// <summary>
    /// Resend email verification OTP
    /// </summary>
    [HttpPost("resend-verification")]
    public async Task<IActionResult> ResendVerification([FromBody] ResendVerificationDto resendDto)
    {
        try
        {
            await _authService.SendVerificationEmailAsync(resendDto.Email);

            return Ok(new BaseResponse<object>
            {
                Success = true,
                Message = "Verification code has been sent to your email. It will expire in 5 minutes.",
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    #endregion

    #region Password Reset

    [HttpPost("forgot-password")]
    public async Task<IActionResult> ForgotPassword([FromBody] RequestOtpDto requestOtpDto)
    {
        try
        {
            // Check if user exists
            var user = await _authService.GetUserByEmailAsync(requestOtpDto.Email);
            if (user == null)
            {
                // Don't reveal if user exists or not for security
                return Ok(new BaseResponse<object>
                {
                    Success = true,
                    Message = "If the email exists, an OTP code has been sent.",
                    StatusCode = 200
                });
            }

            // Generate and send OTP
            await _otpService.GenerateAndSendOtpAsync(requestOtpDto.Email, "ForgotPassword");

            return Ok(new BaseResponse<object>
            {
                Success = true,
                Message = "OTP code has been sent to your email. It will expire in 5 minutes.",
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto resetPasswordDto)
    {
        try
        {
            // Verify OTP first
            var isValid = await _otpService.VerifyOtpAsync(
                resetPasswordDto.Email, 
                resetPasswordDto.OtpCode, 
                "ForgotPassword"
            );

            if (!isValid)
            {
                return BadRequest(new BaseResponse<object>
                {
                    Success = false,
                    Message = "Invalid or expired OTP code",
                    StatusCode = 400
                });
            }

            // Reset password
            await _authService.ResetPasswordAsync(resetPasswordDto);

            // Invalidate OTP
            await _otpService.InvalidateOtpAsync(resetPasswordDto.Email, "ForgotPassword");

            return Ok(new BaseResponse<object>
            {
                Success = true,
                Message = "Password reset successfully. You can now login with your new password.",
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    /// <summary>
    /// Request OTP for changing password
    /// </summary>
    [Authorize]
    [HttpPost("request-change-password-otp")]
    public async Task<IActionResult> RequestChangePasswordOtp()
    {
        try
        {
            var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "Invalid user token",
                    StatusCode = 401
                });
            }

            var user = await _authService.GetUserByIdAsync(userId);
            if (user == null)
            {
                return NotFound(new BaseResponse<object>
                {
                    Success = false,
                    Message = "User not found",
                    StatusCode = 404
                });
            }

            await _otpService.GenerateAndSendOtpAsync(user.Email, "ChangePassword");

            return Ok(new BaseResponse<object>
            {
                Success = true,
                Message = "OTP code has been sent to your email. It will expire in 5 minutes.",
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    /// <summary>
    /// Change password with OTP verification
    /// </summary>
    [Authorize]
    [HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto changePasswordDto)
    {
        try
        {
            var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "Invalid user token",
                    StatusCode = 401
                });
            }

            await _authService.ChangePasswordAsync(userId, changePasswordDto);

            return Ok(new BaseResponse<object>
            {
                Success = true,
                Message = "Password changed successfully",
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    #endregion

    #region OAuth Login

    [HttpPost("google-login")]
    public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginDto googleLoginDto)
    {
        try
        {
            // Verify Google ID Token and get user info
            var providerUserInfo = await _oauthService.VerifyGoogleTokenAsync(googleLoginDto.IdToken);

            // Create ExternalLoginDto with verified Google data
            var externalLoginDto = new ExternalLoginDto
            {
                Provider = providerUserInfo.Provider,
                AccessToken = googleLoginDto.IdToken,
                IdToken = googleLoginDto.IdToken
            };

            // Login or create user
            var result = await _authService.ExternalLoginAsync(externalLoginDto);

            // If 2FA is required
            if (result.Require2FA)
            {
                return Ok(new BaseResponse<AuthResponseDto>
                {
                    Success = true,
                    Message = "2FA code required",
                    Data = result,
                    StatusCode = 200
                });
            }

            // Get user to generate JWT
            var user = await _authService.GetUserByProviderAsync(providerUserInfo.Provider, providerUserInfo.ProviderId);
            if (user == null)
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "Login failed",
                    StatusCode = 401
                });
            }

            // Generate JWT token
            var token = await _authService.GenerateJwtTokenAsync(user);

            // Set HttpOnly Cookie
            HttpContext.Response.Cookies.Append("accessToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddMinutes(60)
            });

            return Ok(new BaseResponse<AuthResponseDto>
            {
                Success = true,
                Message = "Login with Google successful",
                Data = result,
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return Unauthorized(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 401
            });
        }
    }

    [HttpPost("external-login")]
    public async Task<IActionResult> ExternalLogin([FromBody] ExternalLoginDto externalLoginDto)
    {
        try
        {
            // Verify token with provider and login/create user
            // Provider verification is handled inside ExternalLoginAsync
            var result = await _authService.ExternalLoginAsync(externalLoginDto);

            // If 2FA is required
            if (result.Require2FA)
            {
                return Ok(new BaseResponse<AuthResponseDto>
                {
                    Success = true,
                    Message = "2FA code required",
                    Data = result,
                    StatusCode = 200
                });
            }

            // Get user by UserId to generate JWT
            var user = await _authService.GetUserByIdAsync(result.UserId);
            
            if (user == null)
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "Login failed",
                    StatusCode = 401
                });
            }

            // Generate JWT token
            var token = await _authService.GenerateJwtTokenAsync(user);

            // Set HttpOnly Cookie
            HttpContext.Response.Cookies.Append("accessToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddMinutes(60)
            });

            return Ok(new BaseResponse<AuthResponseDto>
            {
                Success = true,
                Message = $"Login with {externalLoginDto.Provider} successful",
                Data = result,
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return Unauthorized(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 401
            });
        }
    }

    #region 2FA Endpoints

    [HttpPost("enable-2fa")]
    [Authorize]
    public async Task<IActionResult> EnableTwoFactor()
    {
        try
        {
            var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "User not authenticated",
                    StatusCode = 401
                });
            }

            var result = await _authService.EnableTwoFactorAsync(userId);

            return Ok(new BaseResponse<Enable2FaResponseDto>
            {
                Success = true,
                Message = "2FA setup initiated. Please scan the QR code with your authenticator app and verify the code.",
                Data = result,
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    [HttpPost("activate-2fa")]
    [Authorize]
    public async Task<IActionResult> VerifyAndActivateTwoFactor([FromBody] Verify2FaDto verify2FaDto)
    {
        try
        {
            var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "User not authenticated",
                    StatusCode = 401
                });
            }

            await _authService.VerifyAndActivateTwoFactorAsync(userId, verify2FaDto.Code);

            return Ok(new BaseResponse<object>
            {
                Success = true,
                Message = "2FA has been successfully enabled for your account",
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    [HttpPost("disable-2fa")]
    [Authorize]
    public async Task<IActionResult> DisableTwoFactor([FromBody] Disable2FaDto disable2FaDto)
    {
        try
        {
            var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out var userId))
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "User not authenticated",
                    StatusCode = 401
                });
            }

            await _authService.DisableTwoFactorAsync(userId, disable2FaDto.Password);

            return Ok(new BaseResponse<object>
            {
                Success = true,
                Message = "2FA has been successfully disabled",
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    #endregion

    #region Exchange Login (Binance/OKX)

    /// <summary>
    /// Login or register using Binance API key
    /// </summary>
    [HttpPost("binance-login")]
    public async Task<IActionResult> BinanceLogin([FromBody] BinanceLoginDto dto)
    {
        try
        {
            var result = await _authService.BinanceLoginAsync(dto);

            // Get the user that was just created or found
            var user = await _authService.GetUserByIdAsync(result.UserId);
            if (user == null)
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "Login failed",
                    StatusCode = 401
                });
            }

            // Generate JWT token
            var token = await _authService.GenerateJwtTokenAsync(user);

            // Set HttpOnly cookie
            Response.Cookies.Append("accessToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddHours(24)
            });

            return Ok(new BaseResponse<AuthResponseDto>
            {
                Success = true,
                Message = "Successfully logged in with Binance",
                Data = result,
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    /// <summary>
    /// Login or register using OKX API key
    /// </summary>
    [HttpPost("okx-login")]
    public async Task<IActionResult> OkxLogin([FromBody] OkxLoginDto dto)
    {
        try
        {
            var result = await _authService.OkxLoginAsync(dto);

            // Get the user that was just created or found
            var user = await _authService.GetUserByIdAsync(result.UserId);
            if (user == null)
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "Login failed",
                    StatusCode = 401
                });
            }

            // Generate JWT token
            var token = await _authService.GenerateJwtTokenAsync(user);

            // Set HttpOnly cookie
            Response.Cookies.Append("accessToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddHours(24)
            });

            return Ok(new BaseResponse<AuthResponseDto>
            {
                Success = true,
                Message = "Successfully logged in with OKX",
                Data = result,
                StatusCode = 200
            });
        }
        catch (Exception ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
    }

    #endregion Exchange Login

    #region Wallet Authentication

    [HttpGet("wallet/nonce")]
    public async Task<IActionResult> GetWalletNonce([FromQuery] string walletAddress)
    {
        try
        {
            var nonceResponse = await _walletAuthService.GenerateNonceAsync(walletAddress);

            return Ok(new BaseResponse<WalletNonceResponseDto>
            {
                Success = true,
                Message = "Nonce generated successfully. Sign the message with your wallet.",
                Data = nonceResponse,
                StatusCode = 200
            });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 400
            });
        }
        catch (Exception)
        {
            return StatusCode(500, new BaseResponse<object>
            {
                Success = false,
                Message = "Failed to generate nonce",
                StatusCode = 500
            });
        }
    }

    [HttpPost("wallet/login")]
    public async Task<IActionResult> WalletLogin([FromBody] WalletLoginDto walletLoginDto)
    {
        try
        {
            // Verify signature and get/create user
            var result = await _walletAuthService.VerifySignatureAsync(
                walletLoginDto.WalletAddress,
                walletLoginDto.Signature,
                walletLoginDto.Nonce
            );

            // If 2FA is required
            if (result.Require2FA)
            {
                return Ok(new BaseResponse<AuthResponseDto>
                {
                    Success = true,
                    Message = "2FA code required",
                    Data = result,
                    StatusCode = 200
                });
            }

            // Get user to generate JWT
            var user = await _walletAuthService.GetUserByWalletAsync(walletLoginDto.WalletAddress);
            if (user == null)
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "Wallet authentication failed",
                    StatusCode = 401
                });
            }

            // Generate JWT token
            var token = await _authService.GenerateJwtTokenAsync(user);

            // Set HttpOnly Cookie
            HttpContext.Response.Cookies.Append("accessToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddMinutes(60)
            });

            return Ok(new BaseResponse<AuthResponseDto>
            {
                Success = true,
                Message = "Wallet authentication successful",
                Data = result,
                StatusCode = 200
            });
        }
        catch (UnauthorizedAccessException ex)
        {
            return Unauthorized(new BaseResponse<object>
            {
                Success = false,
                Message = ex.Message,
                StatusCode = 401
            });
        }
        catch (Exception)
        {
            return StatusCode(500, new BaseResponse<object>
            {
                Success = false,
                Message = "Wallet authentication failed",
                StatusCode = 500
            });
        }
    }

    #endregion

    #endregion
}
