# Build stage
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy solution and project files
COPY AutomatedCryptoTradingPlatform.sln ./
COPY AutomatedCryptoTradingPlatform.API/AutomatedCryptoTradingPlatform.API.csproj AutomatedCryptoTradingPlatform.API/
COPY AutomatedCryptoTradingPlatform.Core/AutomatedCryptoTradingPlatform.Core.csproj AutomatedCryptoTradingPlatform.Core/
COPY AutomatedCryptoTradingPlatform.Infrastructure/AutomatedCryptoTradingPlatform.Infrastructure.csproj AutomatedCryptoTradingPlatform.Infrastructure/

# Restore dependencies
RUN dotnet restore

# Copy source code
COPY . .

# Build the application
WORKDIR /src/AutomatedCryptoTradingPlatform.API
RUN dotnet build -c Release -o /app/build

# Publish stage
FROM build AS publish
RUN dotnet publish -c Release -o /app/publish /p:UseAppHost=false

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app

# Expose ports
EXPOSE 8080
EXPOSE 8081

# Copy published files
COPY --from=publish /app/publish .

# Set environment variables
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

# Run the application
ENTRYPOINT ["dotnet", "AutomatedCryptoTradingPlatform.API.dll"]
