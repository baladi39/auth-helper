using AuthHelper.Models;

namespace AuthHelper.Repositories;


public interface IWeatherForecastRepository
{
    Task<IEnumerable<WeatherForecast>> GetWeatherForecastsAsync(int count = 5);
}

public class WeatherForecastRepository : IWeatherForecastRepository
{
    private static readonly string[] Summaries = new[]
    {
        "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
    };

    // In-memory storage for demo purposes - in a real app, this would be replaced with database access
    private static readonly List<WeatherForecast> _forecasts = [];

    public async Task<IEnumerable<WeatherForecast>> GetWeatherForecastsAsync(int count = 5)
    {
        // Simulate async operation
        await Task.Delay(1);

        // Generate random forecasts if none exist
        if (!_forecasts.Any())
        {
            var generatedForecasts = Enumerable.Range(1, count).Select(index => new WeatherForecast
            {
                Date = DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
                TemperatureC = Random.Shared.Next(-20, 55),
                Summary = Summaries[Random.Shared.Next(Summaries.Length)]
            }).ToList();

            _forecasts.AddRange(generatedForecasts);
        }

        return _forecasts.Take(count);
    }

}