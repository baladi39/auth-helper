using AuthHelper.Models;
using Microsoft.Extensions.Options;
using System.Text;
using System.Text.Json;

namespace AuthHelper.Services
{
    public interface IAuthService
    {
        Task<LoginResponse> LoginAsync(LoginRequest loginRequest);
        Task<SignupResponse> SignupAsync(SignupRequest signupRequest);
        Task<UserInfo> GetUserInfoAsync(string accessToken);
        Auth0LoginUrlResponse GetAuth0LoginUrl(Auth0LoginUrlRequest? request = null);
        Task<Auth0CallbackResponse> HandleAuth0CallbackAsync(Auth0CallbackRequest callbackRequest);
    }

    public class AuthService : IAuthService
    {
        private readonly HttpClient _httpClient;
        private readonly Auth0Settings _auth0Settings;
        private readonly ILogger<AuthService> _logger;

        public AuthService(HttpClient httpClient, IOptions<Auth0Settings> auth0Settings, ILogger<AuthService> logger)
        {
            _httpClient = httpClient;
            _auth0Settings = auth0Settings.Value;
            _logger = logger;
        }

        public async Task<LoginResponse> LoginAsync(LoginRequest loginRequest)
        {
            try
            {
                // Prepare the request for Auth0's Resource Owner Password Grant
                var tokenRequest = new
                {
                    grant_type = "password",
                    username = loginRequest.Email,
                    password = loginRequest.Password,
                    client_id = _auth0Settings.ClientId,
                    client_secret = _auth0Settings.ClientSecret,
                    audience = _auth0Settings.Audience,
                    scope = "openid profile email"
                };

                var json = JsonSerializer.Serialize(tokenRequest);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync($"https://{_auth0Settings.Domain}/oauth/token", content);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError($"Auth0 login failed: {response.StatusCode}, {errorContent}");
                    throw new UnauthorizedAccessException("Invalid credentials");
                }

                var responseContent = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<Auth0TokenResponse>(responseContent);

                if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.access_token))
                {
                    throw new InvalidOperationException("Invalid token response from Auth0");
                }

                // Get user information
                var userInfo = await GetUserInfoAsync(tokenResponse.access_token);

                return new LoginResponse
                {
                    AccessToken = tokenResponse.access_token,
                    TokenType = tokenResponse.token_type,
                    ExpiresIn = tokenResponse.expires_in,
                    User = userInfo
                };
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP error during Auth0 login");
                throw new InvalidOperationException("Authentication service unavailable", ex);
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "JSON parsing error during Auth0 login");
                throw new InvalidOperationException("Invalid response from authentication service", ex);
            }
        }

        public async Task<SignupResponse> SignupAsync(SignupRequest signupRequest)
        {
            try
            {
                // Auth0 Database Signup API payload - simplified
                var signupPayload = new
                {
                    client_id = _auth0Settings.ClientId,
                    email = signupRequest.Email,
                    password = signupRequest.Password,
                    connection = "Username-Password-Authentication"
                };

                var json = JsonSerializer.Serialize(signupPayload);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var signupResponse = await _httpClient.PostAsync($"https://{_auth0Settings.Domain}/dbconnections/signup", content);
                var responseContent = await signupResponse.Content.ReadAsStringAsync();

                _logger.LogInformation($"Auth0 signup response: {signupResponse.StatusCode}, Content: {responseContent}");

                if (!signupResponse.IsSuccessStatusCode)
                {
                    _logger.LogError($"Auth0 signup failed: {signupResponse.StatusCode}, {responseContent}");

                    // Parse the specific Auth0 error
                    try
                    {
                        var errorResponse = JsonSerializer.Deserialize<JsonElement>(responseContent);
                        if (errorResponse.TryGetProperty("code", out var codeElement))
                        {
                            var errorCode = codeElement.GetString();
                            if (errorCode == "user_exists")
                            {
                                throw new InvalidOperationException("User with this email already exists");
                            }
                        }

                        if (errorResponse.TryGetProperty("description", out var descElement))
                        {
                            var description = descElement.GetString();
                            _logger.LogError($"Auth0 signup error description: {description}");
                            throw new InvalidOperationException($"Signup failed: {description}");
                        }
                    }
                    catch (JsonException)
                    {
                        // If we can't parse the error, fall back to generic message
                    }

                    if (signupResponse.StatusCode == System.Net.HttpStatusCode.BadRequest)
                    {
                        throw new InvalidOperationException("Invalid signup data provided. Please check your input.");
                    }

                    throw new InvalidOperationException("Signup service unavailable");
                }

                // Auth0 signup endpoint returns user info, not tokens
                // Parse the signup response to get user information
                var signupData = JsonSerializer.Deserialize<JsonElement>(responseContent);

                var userInfo = new UserInfo
                {
                    UserId = signupData.TryGetProperty("_id", out var idElement) ? idElement.GetString() ?? "" : "",
                    Email = signupData.TryGetProperty("email", out var emailElement) ? emailElement.GetString() ?? "" : signupRequest.Email,
                    Name = signupRequest.Email, // Use email as name since Auth0 signup doesn't return name
                    Picture = ""
                };

                return new SignupResponse
                {
                    AccessToken = "", // No token provided during signup
                    TokenType = "Bearer",
                    ExpiresIn = 0,
                    User = userInfo,
                    Message = "User created successfully. Please log in to continue."
                };
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP error during Auth0 signup");
                throw new InvalidOperationException("Signup service unavailable", ex);
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "JSON parsing error during Auth0 signup");
                throw new InvalidOperationException("Invalid response from signup service", ex);
            }
        }

        public async Task<UserInfo> GetUserInfoAsync(string accessToken)
        {
            try
            {
                _httpClient.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

                var response = await _httpClient.GetAsync($"https://{_auth0Settings.Domain}/userinfo");

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError($"Failed to get user info: {response.StatusCode}");
                    throw new UnauthorizedAccessException("Failed to retrieve user information");
                }

                var responseContent = await response.Content.ReadAsStringAsync();
                var userProfile = JsonSerializer.Deserialize<Auth0UserProfile>(responseContent);

                if (userProfile == null)
                {
                    throw new InvalidOperationException("Invalid user profile response from Auth0");
                }

                return new UserInfo
                {
                    UserId = userProfile.sub,
                    Email = userProfile.email,
                    Name = userProfile.name ?? userProfile.email,
                    Picture = userProfile.picture
                };
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP error during user info retrieval");
                throw new InvalidOperationException("User information service unavailable", ex);
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "JSON parsing error during user info retrieval");
                throw new InvalidOperationException("Invalid response from user information service", ex);
            }
        }

        public Auth0LoginUrlResponse GetAuth0LoginUrl(Auth0LoginUrlRequest? request = null)
        {
            try
            {
                // Generate a random state parameter for security
                var state = request?.State ?? Guid.NewGuid().ToString("N");

                // Use provided redirect URI or fall back to configured one
                var redirectUri = request?.RedirectUri ?? _auth0Settings.RedirectUri;

                if (string.IsNullOrEmpty(redirectUri))
                {
                    throw new InvalidOperationException("Redirect URI must be configured in Auth0Settings or provided in the request");
                }

                // Build the authorization URL
                var authUrlBuilder = new StringBuilder($"https://{_auth0Settings.Domain}/authorize");
                authUrlBuilder.Append($"?response_type=code");
                authUrlBuilder.Append($"&client_id={Uri.EscapeDataString(_auth0Settings.ClientId)}");
                authUrlBuilder.Append($"&redirect_uri={Uri.EscapeDataString(redirectUri)}");
                authUrlBuilder.Append($"&scope=openid%20profile%20email");
                authUrlBuilder.Append($"&state={Uri.EscapeDataString(state)}");

                // Add audience if specified
                if (!string.IsNullOrEmpty(_auth0Settings.Audience))
                {
                    authUrlBuilder.Append($"&audience={Uri.EscapeDataString(_auth0Settings.Audience)}");
                }

                // Add connection if specified (for social logins, etc.)
                if (!string.IsNullOrEmpty(request?.Connection))
                {
                    authUrlBuilder.Append($"&connection={Uri.EscapeDataString(request.Connection)}");
                }

                var loginUrl = authUrlBuilder.ToString();

                _logger.LogInformation("Generated Auth0 login URL for client_id: {ClientId}", _auth0Settings.ClientId);

                return new Auth0LoginUrlResponse
                {
                    LoginUrl = loginUrl,
                    State = state
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating Auth0 login URL");
                throw new InvalidOperationException("Failed to generate Auth0 login URL", ex);
            }
        }

        public async Task<Auth0CallbackResponse> HandleAuth0CallbackAsync(Auth0CallbackRequest callbackRequest)
        {
            try
            {
                // Prepare the token exchange request
                var tokenRequest = new
                {
                    grant_type = "authorization_code",
                    client_id = _auth0Settings.ClientId,
                    client_secret = _auth0Settings.ClientSecret,
                    code = callbackRequest.Code,
                    redirect_uri = callbackRequest.RedirectUri ?? "http://localhost:5018"
                };

                var json = JsonSerializer.Serialize(tokenRequest);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                var response = await _httpClient.PostAsync($"https://{_auth0Settings.Domain}/oauth/token", content);

                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError($"Auth0 token exchange failed: {response.StatusCode}, {errorContent}");
                    throw new InvalidOperationException("Failed to exchange authorization code for tokens");
                }

                var responseContent = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonSerializer.Deserialize<Auth0TokenResponse>(responseContent);

                if (tokenResponse == null || string.IsNullOrEmpty(tokenResponse.access_token))
                {
                    throw new InvalidOperationException("Invalid token response from Auth0");
                }

                // Get user information using the access token
                var userInfo = await GetUserInfoAsync(tokenResponse.access_token);

                return new Auth0CallbackResponse
                {
                    AccessToken = tokenResponse.access_token,
                    RefreshToken = tokenResponse.refresh_token ?? string.Empty,
                    TokenType = tokenResponse.token_type ?? "Bearer",
                    ExpiresIn = tokenResponse.expires_in,
                    Scope = tokenResponse.scope ?? string.Empty,
                    User = userInfo
                };
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP error during Auth0 callback processing");
                throw new InvalidOperationException("Authentication service unavailable", ex);
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "JSON parsing error during Auth0 callback processing");
                throw new InvalidOperationException("Invalid response from authentication service", ex);
            }
        }
    }
}