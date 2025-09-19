using AuthHelper.Models;
using AuthHelper.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthHelper.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IAuthService authService, ILogger<AuthController> logger)
        {
            _authService = authService;
            _logger = logger;
        }

        /// <summary>
        /// Authenticate user with email and password
        /// </summary>
        /// <param name="loginRequest">Login credentials</param>
        /// <returns>Access token and user information</returns>
        [HttpPost("login")]
        public async Task<ActionResult<LoginResponse>> Login([FromBody] LoginRequest loginRequest)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var response = await _authService.LoginAsync(loginRequest);
                return Ok(response);
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Login attempt failed for email: {Email}", loginRequest.Email);
                return Unauthorized(new { message = "Invalid email or password" });
            }
            catch (InvalidOperationException ex)
            {
                _logger.LogError(ex, "Login error for email: {Email}", loginRequest.Email);
                return StatusCode(500, new { message = "Authentication service error" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during login for email: {Email}", loginRequest.Email);
                return StatusCode(500, new { message = "An unexpected error occurred" });
            }
        }

        /// <summary>
        /// Register a new user with email and password
        /// </summary>
        /// <param name="signupRequest">User registration details</param>
        /// <returns>Access token and user information</returns>
        [HttpPost("signup")]
        public async Task<ActionResult<SignupResponse>> Signup([FromBody] SignupRequest signupRequest)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }

                var response = await _authService.SignupAsync(signupRequest);
                return Ok(response);
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("already exists"))
            {
                _logger.LogWarning(ex, "Signup attempt with existing email: {Email}", signupRequest.Email);
                return Conflict(new { message = "User with this email already exists" });
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("Invalid signup data"))
            {
                _logger.LogWarning(ex, "Invalid signup data for email: {Email}", signupRequest.Email);
                return BadRequest(new { message = "Invalid signup data provided" });
            }
            catch (InvalidOperationException ex)
            {
                _logger.LogError(ex, "Signup service error for email: {Email}", signupRequest.Email);
                return StatusCode(500, new { message = "Signup service error" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during signup for email: {Email}", signupRequest.Email);
                return StatusCode(500, new { message = "An unexpected error occurred" });
            }
        }

        /// <summary>
        /// Get current user information (requires authentication)
        /// </summary>
        /// <returns>Current user information</returns>
        [HttpGet("me")]
        [Authorize]
        public async Task<ActionResult<UserInfo>> GetCurrentUser()
        {
            try
            {
                var authHeader = Request.Headers.Authorization.FirstOrDefault();
                if (authHeader == null || !authHeader.StartsWith("Bearer "))
                {
                    return Unauthorized(new { message = "Authorization header missing or invalid" });
                }

                var token = authHeader.Substring("Bearer ".Length);
                var userInfo = await _authService.GetUserInfoAsync(token);

                return Ok(userInfo);
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogWarning(ex, "Unauthorized access to user info");
                return Unauthorized(new { message = "Invalid or expired token" });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error retrieving current user info");
                return StatusCode(500, new { message = "An error occurred while retrieving user information" });
            }
        }

        /// <summary>
        /// Get Auth0 login URL for web authentication
        /// </summary>
        /// <param name="request">Optional login URL parameters</param>
        /// <returns>Auth0 authorization URL and state parameter</returns>
        [HttpPost("login-url")]
        public ActionResult<Auth0LoginUrlResponse> GetAuth0LoginUrl([FromBody] Auth0LoginUrlRequest? request = null)
        {
            try
            {
                var response = _authService.GetAuth0LoginUrl(request);
                return Ok(response);
            }
            catch (InvalidOperationException ex)
            {
                _logger.LogError(ex, "Error generating Auth0 login URL");
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error generating Auth0 login URL");
                return StatusCode(500, new { message = "An unexpected error occurred" });
            }
        }

        /// <summary>
        /// Redirect to Auth0 login URL for web authentication
        /// </summary>
        /// <param name="redirectUri">Optional redirect URI (default: http://localhost:5018/api/Auth/callback)</param>
        /// <param name="state">Optional state parameter (default: my-custom-state)</param>
        /// <param name="connection">Optional connection type (default: Username-Password-Authentication)</param>
        /// <returns>Redirect to Auth0 authorization URL</returns>
        [HttpGet("login")]
        public ActionResult RedirectToAuth0Login(
            [FromQuery] string? redirectUri = null,
            [FromQuery] string? state = null,
            [FromQuery] string? connection = null)
        {
            try
            {
                // Get the base URL from the current request
                var baseUrl = $"{Request.Scheme}://{Request.Host}";

                // Apply default values
                var request = new Auth0LoginUrlRequest
                {
                    RedirectUri = redirectUri ?? $"{baseUrl}/api/Auth/callback",
                    State = state ?? "my-custom-state",
                    Connection = connection ?? "Username-Password-Authentication"
                };

                var response = _authService.GetAuth0LoginUrl(request);
                return Redirect(response.LoginUrl);
            }
            catch (InvalidOperationException ex)
            {
                _logger.LogError(ex, "Error generating Auth0 login URL for redirect");
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error generating Auth0 login URL for redirect");
                return StatusCode(500, new { message = "An unexpected error occurred" });
            }
        }

        /// <summary>
        /// Handle Auth0 callback and exchange authorization code for tokens
        /// </summary>
        /// <param name="code">Authorization code from Auth0 callback</param>
        /// <param name="state">State parameter from Auth0 callback</param>
        /// <param name="redirectUri">Optional redirect URI used in the authorization request</param>
        /// <returns>Access token, refresh token, and user information</returns>
        [HttpGet("callback")]
        public async Task<ActionResult<Auth0CallbackResponse>> HandleAuth0Callback(
            [FromQuery] string code,
            [FromQuery] string? state = null,
            [FromQuery] string? redirectUri = null)
        {
            try
            {
                if (string.IsNullOrEmpty(code))
                {
                    return BadRequest(new { message = "Authorization code is required" });
                }

                var callbackRequest = new Auth0CallbackRequest
                {
                    Code = code,
                    State = state ?? string.Empty,
                    RedirectUri = redirectUri
                };

                var response = await _authService.HandleAuth0CallbackAsync(callbackRequest);
                return Ok(response);
            }
            catch (InvalidOperationException ex)
            {
                _logger.LogError(ex, "Error processing Auth0 callback");
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error processing Auth0 callback");
                return StatusCode(500, new { message = "An unexpected error occurred" });
            }
        }

        /// <summary>
        /// Health check endpoint for the auth service
        /// </summary>
        /// <returns>Service status</returns>
        [HttpGet("health")]
        public IActionResult Health()
        {
            return Ok(new { status = "healthy", service = "auth", timestamp = DateTime.UtcNow });
        }

        /// <summary>
        /// Receive user data payload from Node.js and log it
        /// </summary>
        /// <param name="userDataPayload">User data from Node.js</param>
        /// <returns>Confirmation of received data</returns>
        [HttpPost("receive-user-data")]
        public ActionResult ReceiveUserData([FromBody] UserDataPayload userDataPayload)
        {
            try
            {
                // Log the received payload to the logger
                _logger.LogInformation("Received user data payload: {@UserDataPayload}", userDataPayload);

                // Write to console as well
                Console.WriteLine("=== User Data Received ===");
                Console.WriteLine($"User ID: {userDataPayload.User_Id}");
                Console.WriteLine($"Email: {userDataPayload.Email}");
                Console.WriteLine($"Name: {userDataPayload.Name}");
                Console.WriteLine($"Nickname: {userDataPayload.Nickname}");
                Console.WriteLine($"Picture: {userDataPayload.Picture}");
                Console.WriteLine($"Email Verified: {userDataPayload.Email_Verified}");
                Console.WriteLine($"Login Count: {userDataPayload.Login_Count}");
                Console.WriteLine($"Last Login: {userDataPayload.Last_Login}");
                Console.WriteLine($"User Metadata: {System.Text.Json.JsonSerializer.Serialize(userDataPayload.User_Metadata)}");
                Console.WriteLine($"App Metadata: {System.Text.Json.JsonSerializer.Serialize(userDataPayload.App_Metadata)}");
                Console.WriteLine($"Connection: {userDataPayload.Connection}");
                Console.WriteLine($"Connection Strategy: {userDataPayload.Connection_Strategy}");
                Console.WriteLine($"Client ID: {userDataPayload.Client_Id}");
                Console.WriteLine($"Client Name: {userDataPayload.Client_Name}");
                Console.WriteLine("========================");

                return Ok(new { message = "User data received and logged successfully", timestamp = DateTime.UtcNow });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing user data payload");
                Console.WriteLine($"Error processing user data: {ex.Message}");
                return StatusCode(500, new { message = "Error processing user data" });
            }
        }
    }
}