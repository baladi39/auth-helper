using Microsoft.AspNetCore.Mvc;
using auth_tester.Models;
using auth_tester.Services;

namespace auth_tester.Controllers;

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
            var forecasts = await _weatherForecastService.GetWeatherForecastsAsync(count);
            Console.WriteLine("Successfully retrieved weather forecasts.");
            return Ok(forecasts);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error occurred while getting weather forecasts");
            return StatusCode(500, "An error occurred while processing your request");
        }
    }
}
