using AutomatedCryptoTradingPlatform.Core.Entities;
using AutomatedCryptoTradingPlatform.Core.Helpers; 
using Microsoft.EntityFrameworkCore;

namespace AutomatedCryptoTradingPlatform.Infrastructure.Data;

public static class DbSeeder
{
    public static async Task SeedAdminAsync(AppDbContext db)
    {
        const string email = "admin@local.com";
        const string password = "Admin@123";

        var exists = await db.Users.AnyAsync(x => x.Email == email);
        if (exists) return;

        db.Users.Add(new User
        {
            Email = email,
            Username = "Administrator",
            PasswordHash = CryptographyHelper.HashPassword(password), 
            Status = "active",
            Role = "admin",
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow
        });

        await db.SaveChangesAsync();
    }
}
