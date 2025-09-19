using auth_tester.Models;
using auth_tester.Repositories;

namespace auth_tester.Services;

public interface IWeatherForecastService
{
    Task<IEnumerable<WeatherForecast>> GetWeatherForecastsAsync(int count = 5);
}

public class WeatherForecastService : IWeatherForecastService
{
    private readonly IWeatherForecastRepository _repository;
    private readonly ILogger<WeatherForecastService> _logger;

    public WeatherForecastService(IWeatherForecastRepository repository, ILogger<WeatherForecastService> logger)
    {
        _repository = repository;
        _logger = logger;
    }

    public async Task<IEnumerable<WeatherForecast>> GetWeatherForecastsAsync(int count = 5)
    {
        _logger.LogInformation("Getting {Count} weather forecasts", count);

        if (count <= 0)
        {
            _logger.LogWarning("Invalid count requested: {Count}. Returning empty result.", count);
            return Enumerable.Empty<WeatherForecast>();
        }

        if (count > 50)
        {
            _logger.LogWarning("Count requested ({Count}) exceeds maximum allowed (50). Limiting to 50.", count);
            count = 50;
        }

        var forecasts = await _repository.GetWeatherForecastsAsync(count);
        _logger.LogInformation("Successfully retrieved {Count} weather forecasts", forecasts.Count());

        return forecasts;
    }

}