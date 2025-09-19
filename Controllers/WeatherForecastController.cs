using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using AuthHelper.Models;
using AuthHelper.Services;

namespace AuthHelper.Controllers;

[ApiController]
[Route("[controller]")]
public class WeatherForecastController : ControllerBase
{
    private readonly IWeatherForecastService _weatherForecastService;
    private readonly ILogger<WeatherForecastController> _logger;

    public WeatherForecastController(IWeatherForecastService weatherForecastService, ILogger<WeatherForecastController> logger)
    {
        _weatherForecastService = weatherForecastService;
        _logger = logger;
    }

    [HttpGet(Name = "GetWeatherForecast")]
    public async Task<ActionResult<IEnumerable<WeatherForecast>>> Get([FromQuery] int count = 5)
    {
        try
        {
            // Get the authenticated user's identity
            var userId = User.Identity?.Name ?? "unknown";
            _logger.LogInformation("User {UserId} requested {Count} weather forecasts", userId, count);

            var forecasts = await _weatherForecastService.GetWeatherForecastsAsync(count);
            Console.WriteLine($"Successfully retrieved weather forecasts for user: {userId}");
            return Ok(forecasts);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while getting weather forecasts");
            return StatusCode(500, "An error occurred while processing your request");
        }
    }

    /// <summary>
    /// Get a specific weather forecast by ID (protected endpoint)
    /// </summary>
    /// <param name="id">Forecast ID</param>
    /// <returns>Weather forecast</returns>
    [HttpGet("{id}")]
    [Authorize]
    public async Task<ActionResult<WeatherForecast>> GetById(int id)
    {
        try
        {
            var userId = User.Identity?.Name ?? "unknown";
            _logger.LogInformation("User {UserId} requested weather forecast with ID {Id}", userId, id);

            var forecasts = await _weatherForecastService.GetWeatherForecastsAsync(10);
            var forecast = forecasts.Skip(id).FirstOrDefault();

            if (forecast == null)
            {
                return NotFound($"Weather forecast with ID {id} not found");
            }

            return Ok(forecast);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while getting weather forecast {Id}", id);
            return StatusCode(500, "An error occurred while processing your request");
        }
    }
}
