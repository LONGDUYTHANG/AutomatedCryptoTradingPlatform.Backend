using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Configuration;
using MimeKit;

namespace AutomatedCryptoTradingPlatform.Core.Services;

public class EmailService : IEmailService
{
    private readonly IConfiguration _configuration;

    public EmailService(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task SendEmailAsync(string toEmail, string subject, string htmlBody)
    {
        var emailSettings = _configuration.GetSection("EmailSettings");
        var senderEmail = emailSettings["SenderEmail"] ?? throw new Exception("Sender email not configured");
        var senderName = emailSettings["SenderName"] ?? "Automated Crypto Trading";
        var password = emailSettings["Password"] ?? throw new Exception("Email password not configured");
        var smtpServer = emailSettings["SmtpServer"] ?? "smtp.gmail.com";
        var smtpPort = int.Parse(emailSettings["SmtpPort"] ?? "587");
        var enableSsl = bool.Parse(emailSettings["EnableSsl"] ?? "true");

        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(senderName, senderEmail));
        message.To.Add(new MailboxAddress("", toEmail));
        message.Subject = subject;

        var bodyBuilder = new BodyBuilder
        {
            HtmlBody = htmlBody
        };
        message.Body = bodyBuilder.ToMessageBody();

        using var client = new SmtpClient();
        try
        {
            await client.ConnectAsync(smtpServer, smtpPort, enableSsl ? SecureSocketOptions.StartTls : SecureSocketOptions.None);
            await client.AuthenticateAsync(senderEmail, password);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }
        catch (Exception ex)
        {
            // Log exception here
            throw new Exception($"Failed to send email: {ex.Message}");
        }
    }

    public async Task SendOtpEmailAsync(string toEmail, string otpCode, string purpose)
    {
        var subject = purpose == "ForgotPassword" 
            ? "Reset Your Password - OTP Code" 
            : "Verify Your Email - OTP Code";

        var htmlBody = $@"
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; color: #333; margin-bottom: 30px; }}
        .otp-code {{ font-size: 32px; font-weight: bold; color: #4CAF50; text-align: center; letter-spacing: 5px; padding: 20px; background-color: #f0f0f0; border-radius: 5px; margin: 20px 0; }}
        .message {{ color: #666; line-height: 1.6; margin: 20px 0; }}
        .warning {{ color: #ff5722; font-size: 14px; margin-top: 20px; }}
        .footer {{ text-align: center; margin-top: 30px; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <h2>🔐 Automated Crypto Trading Platform</h2>
        </div>
        <div class='message'>
            <p>Hello,</p>
            <p>You have requested a {(purpose == "ForgotPassword" ? "password reset" : "verification")} code. Please use the following OTP code:</p>
        </div>
        <div class='otp-code'>{otpCode}</div>
        <div class='message'>
            <p>This code will expire in <strong>5 minutes</strong>.</p>
            <p>If you did not request this code, please ignore this email.</p>
        </div>
        <div class='warning'>
            ⚠️ Never share this code with anyone!
        </div>
        <div class='footer'>
            <p>© 2026 Automated Crypto Trading Platform. All rights reserved.</p>
        </div>
    </div>
</body>
</html>";

        await SendEmailAsync(toEmail, subject, htmlBody);
    }
}
