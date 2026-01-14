using AutomatedCryptoTradingPlatform.API.Middlewares;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Repositories;
using AutomatedCryptoTradingPlatform.Core.Interfaces.Services;
using AutomatedCryptoTradingPlatform.Core.Services;
using AutomatedCryptoTradingPlatform.Infrastructure.Repositories;

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

//Cấu hình DI
builder.Services.AddScoped(typeof(IBaseRepository<>), typeof(BaseRepository<>));
builder.Services.AddScoped(typeof(IBaseService<>), typeof(BaseService<>));

// Cấu hình CORS
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
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

app.UseAuthorization();

app.MapControllers();

app.Run();
