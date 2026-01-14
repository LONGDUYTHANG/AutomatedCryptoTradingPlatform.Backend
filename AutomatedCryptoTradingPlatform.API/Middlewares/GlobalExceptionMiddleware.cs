using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Exceptions;

namespace AutomatedCryptoTradingPlatform.API.Middlewares
{
    public class GlobalExceptionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<GlobalExceptionMiddleware> _logger;

        public GlobalExceptionMiddleware(
            RequestDelegate next,
            ILogger<GlobalExceptionMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "An unhandled exception has occurred: {Message}",
                    ex.Message
                );

                await HandleExceptionAsync(context, ex);
            }
        }
        private static Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            context.Response.ContentType = "application/json";

            var response = new BaseResponse<object>
            {
                Success = false,
                StatusCode = StatusCodes.Status500InternalServerError,
                Message = "Đã xảy ra lỗi hệ thống. Vui lòng thử lại sau!",
                Data = null
            };

            // Xử lý ValidationException
            if (exception is ValidationException validationEx)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                response.StatusCode = StatusCodes.Status400BadRequest;
                response.Message = validationEx.Message;
                response.ValidationErrors = validationEx.Errors;
            }
            else
            {
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                response.StatusCode = StatusCodes.Status500InternalServerError;
                response.Message = exception.Message;
            }

            return context.Response.WriteAsJsonAsync(response);
        }

    }
}
