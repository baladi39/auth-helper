using auth_tester.Repositories;
using auth_tester.Services;
using auth_tester.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using DotNetEnv;

// Load environment variables from .env file
Env.Load();

var builder = WebApplication.CreateBuilder(args);

// Add configuration to replace environment variable placeholders
builder.Configuration.AddEnvironmentVariables();

// Debug: Check if environment variables are loaded
Console.WriteLine($"AUTH0_DOMAIN: {Environment.GetEnvironmentVariable("AUTH0_DOMAIN")}");
Console.WriteLine($"AUTH0_CLIENT_ID: {Environment.GetEnvironmentVariable("AUTH0_CLIENT_ID")}");

// Add services to the container.

builder.Services.AddControllers();

// Configure Auth0 settings with environment variable substitution
var auth0Domain = Environment.GetEnvironmentVariable("AUTH0_DOMAIN");
var auth0ClientId = Environment.GetEnvironmentVariable("AUTH0_CLIENT_ID");
var auth0ClientSecret = Environment.GetEnvironmentVariable("AUTH0_CLIENT_SECRET");
var auth0Audience = Environment.GetEnvironmentVariable("AUTH0_AUDIENCE");

// Validate that all required environment variables are set
if (string.IsNullOrEmpty(auth0Domain) ||
    string.IsNullOrEmpty(auth0ClientId) ||
    string.IsNullOrEmpty(auth0ClientSecret) ||
    string.IsNullOrEmpty(auth0Audience))
{
    throw new InvalidOperationException("Auth0 environment variables are not properly configured. Please check your .env file.");
}

var auth0Settings = new Auth0Settings
{
    Domain = auth0Domain,
    ClientId = auth0ClientId,
    ClientSecret = auth0ClientSecret,
    Audience = auth0Audience
};

// Configure Auth0Settings for dependency injection
builder.Services.Configure<Auth0Settings>(options =>
{
    options.Domain = auth0Settings.Domain;
    options.ClientId = auth0Settings.ClientId;
    options.ClientSecret = auth0Settings.ClientSecret;
    options.Audience = auth0Settings.Audience;
});

// Add HTTP client for Auth0 service
builder.Services.AddHttpClient<IAuthService, AuthService>();

// Configure JWT Authentication
if (!string.IsNullOrEmpty(auth0Settings.Domain) && !string.IsNullOrEmpty(auth0Settings.Audience))
{
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.Authority = $"https://{auth0Settings.Domain}/";
            options.Audience = auth0Settings.Audience;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                NameClaimType = ClaimTypes.NameIdentifier,
            };
        });
}

// Add authorization
builder.Services.AddAuthorization();

// Add NSwag services
builder.Services.AddOpenApiDocument(config =>
{
    config.DocumentName = "v1";
    config.Title = "Auth Tester API";
    config.Version = "v1";
    config.Description = "A simple ASP.NET Core Web API for authentication testing";

    // Add JWT authentication to Swagger
    config.AddSecurity("JWT", new NSwag.OpenApiSecurityScheme
    {
        Type = NSwag.OpenApiSecuritySchemeType.ApiKey,
        Name = "Authorization",
        In = NSwag.OpenApiSecurityApiKeyLocation.Header,
        Description = "Type into the textbox: Bearer {your JWT token}."
    });
});

// Register repository and service layers
builder.Services.AddScoped<IWeatherForecastRepository, WeatherForecastRepository>();
builder.Services.AddScoped<IWeatherForecastService, WeatherForecastService>();
builder.Services.AddScoped<IAuthService, AuthService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseOpenApi();
    app.UseSwaggerUi();
}

app.UseHttpsRedirection();

// Add authentication and authorization middleware
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Health check endpoint for Docker
app.MapGet("/health", () => Results.Ok(new { status = "healthy", timestamp = DateTime.UtcNow }));

app.Run();
