using auth_tester.Models;
using auth_tester.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace auth_tester.Controllers
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
        /// Health check endpoint for the auth service
        /// </summary>
        /// <returns>Service status</returns>
        [HttpGet("health")]
        public IActionResult Health()
        {
            return Ok(new { status = "healthy", service = "auth", timestamp = DateTime.UtcNow });
        }
    }
}