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

    public AuthController(
        IAuthService authService, 
        IOtpService otpService,
        IOAuthService oauthService)
    {
        _authService = authService;
        _otpService = otpService;
        _oauthService = oauthService;
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

            // If 2FA is required, don't set cookie yet
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
            var user = await _authService.GetUserByEmailAsync(loginDto.Email);
            if (user == null)
            {
                return Unauthorized(new BaseResponse<object>
                {
                    Success = false,
                    Message = "Invalid credentials",
                    StatusCode = 401
                });
            }

            // Generate JWT token
            var token = await _authService.GenerateJwtTokenAsync(user);

            // Set HttpOnly Cookie
            HttpContext.Response.Cookies.Append("accessToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // Only works with HTTPS
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddMinutes(60)
            });

            return Ok(new BaseResponse<AuthResponseDto>
            {
                Success = true,
                Message = "Login successful",
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
            // Verify Google ID Token
            var externalLoginDto = await _oauthService.VerifyGoogleTokenAsync(googleLoginDto.IdToken);

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
            var user = await _authService.GetUserByProviderAsync(externalLoginDto.Provider, externalLoginDto.ProviderId!);
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
            // For Binance, OKX, and other providers
            // Note: These providers typically require manual API key input or OAuth flow handled by frontend
            
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
            var user = await _authService.GetUserByProviderAsync(
                externalLoginDto.Provider, 
                externalLoginDto.ProviderId!);
            
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

    [HttpPost("verify-2fa")]
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

    #endregion
}
