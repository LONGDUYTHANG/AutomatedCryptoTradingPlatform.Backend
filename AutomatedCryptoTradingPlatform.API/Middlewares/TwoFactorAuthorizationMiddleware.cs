using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using System.Text.Json;

namespace AutomatedCryptoTradingPlatform.API.Middlewares
{
    /// <summary>
    /// Middleware to prevent access to protected endpoints when user has pending 2FA verification
    /// </summary>
    public class TwoFactorAuthorizationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<TwoFactorAuthorizationMiddleware> _logger;

        public TwoFactorAuthorizationMiddleware(
            RequestDelegate next,
            ILogger<TwoFactorAuthorizationMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Check if user is authenticated
            if (context.User.Identity?.IsAuthenticated == true)
            {
                // Check for 2FA pending claim
                var twoFactorPending = context.User.FindFirst("2fa_pending")?.Value;
                
                if (twoFactorPending == "true")
                {
                    // Get the request path
                    var path = context.Request.Path.Value?.ToLower() ?? "";
                    
                    // Only allow access to verify-2fa endpoint and auth endpoints
                    var allowedPaths = new[]
                    {
                        "/api/auth/verify-2fa",
                        "/api/auth/login",
                        "/api/auth/register",
                        "/swagger",
                        "/health"
                    };
                    
                    var isAllowed = allowedPaths.Any(allowedPath => path.Contains(allowedPath));
                    
                    if (!isAllowed)
                    {
                        _logger.LogWarning(
                            "Access denied to {Path} - 2FA verification pending for user {UserId}",
                            path,
                            context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value
                        );
                        
                        context.Response.StatusCode = StatusCodes.Status403Forbidden;
                        context.Response.ContentType = "application/json";
                        
                        var response = new BaseResponse<object>
                        {
                            Success = false,
                            Message = "Two-factor authentication is required. Please complete 2FA verification first.",
                            StatusCode = 403
                        };
                        
                        await context.Response.WriteAsync(
                            JsonSerializer.Serialize(response, new JsonSerializerOptions
                            {
                                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                            })
                        );
                        
                        return;
                    }
                }
            }
            
            await _next(context);
        }
    }
    
    public static class TwoFactorAuthorizationMiddlewareExtensions
    {
        public static IApplicationBuilder UseTwoFactorAuthorization(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<TwoFactorAuthorizationMiddleware>();
        }
    }
}
