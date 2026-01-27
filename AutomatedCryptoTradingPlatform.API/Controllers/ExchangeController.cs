using AutomatedCryptoTradingPlatform.Core.Dtos.Requests;
using AutomatedCryptoTradingPlatform.Core.Dtos.Responses;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AutomatedCryptoTradingPlatform.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class ExchangeController : ControllerBase
{
    private readonly IExchangeKeyService _exchangeKeyService;

    public ExchangeController(IExchangeKeyService exchangeKeyService)
    {
        _exchangeKeyService = exchangeKeyService;
    }

    [HttpPost("connect")]
    public async Task<IActionResult> ConnectExchange([FromBody] ConnectExchangeDto connectDto)
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

            var result = await _exchangeKeyService.ConnectExchangeAsync(userId, connectDto);

            return Ok(new BaseResponse<ExchangeKeyResponseDto>
            {
                Success = true,
                Message = "Exchange connected successfully",
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

    [HttpDelete("disconnect/{keyId}")]
    public async Task<IActionResult> DisconnectExchange(Guid keyId)
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

            await _exchangeKeyService.DisconnectExchangeAsync(userId, keyId);

            return Ok(new BaseResponse<object>
            {
                Success = true,
                Message = "Exchange disconnected successfully",
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

    [HttpGet("list")]
    public async Task<IActionResult> GetExchangeKeys()
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

            var result = await _exchangeKeyService.GetUserExchangeKeysAsync(userId);

            return Ok(new BaseResponse<List<ExchangeKeyResponseDto>>
            {
                Success = true,
                Message = "Exchange keys retrieved successfully",
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

    [HttpPost("verify")]
    public async Task<IActionResult> VerifyConnection([FromBody] ConnectExchangeDto connectDto)
    {
        try
        {
            var result = await _exchangeKeyService.VerifyConnectionAsync(
                connectDto.ExchangeName,
                connectDto.ApiKey,
                connectDto.SecretKey,
                connectDto.Passphrase
            );

            if (!result.IsValid)
            {
                return BadRequest(new BaseResponse<VerifyConnectionResponseDto>
                {
                    Success = false,
                    Message = result.Message,
                    Data = result,
                    StatusCode = 400
                });
            }

            return Ok(new BaseResponse<VerifyConnectionResponseDto>
            {
                Success = true,
                Message = "Connection verified successfully",
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

    [HttpGet("supported")]
    [AllowAnonymous] // Public endpoint
    public async Task<IActionResult> GetSupportedExchanges()
    {
        try
        {
            var result = await _exchangeKeyService.GetSupportedExchangesAsync();

            return Ok(new BaseResponse<List<ExchangeDto>>
            {
                Success = true,
                Message = "Supported exchanges retrieved successfully",
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
}
