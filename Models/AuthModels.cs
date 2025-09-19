using System.ComponentModel.DataAnnotations;

namespace AuthHelper.Models
{
    public class LoginRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        public string Password { get; set; } = string.Empty;
    }

    public class SignupRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        [Required]
        [MinLength(8)]
        public string Password { get; set; } = string.Empty;
    }

    public class LoginResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public string TokenType { get; set; } = "Bearer";
        public int ExpiresIn { get; set; }
        public UserInfo User { get; set; } = new();
    }

    public class SignupResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public string TokenType { get; set; } = "Bearer";
        public int ExpiresIn { get; set; }
        public UserInfo User { get; set; } = new();
        public string Message { get; set; } = "User created successfully";
    }

    public class UserInfo
    {
        public string UserId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Picture { get; set; } = string.Empty;
    }

    public class Auth0TokenResponse
    {
        public string access_token { get; set; } = string.Empty;
        public string token_type { get; set; } = string.Empty;
        public int expires_in { get; set; }
        public string? refresh_token { get; set; }
        public string? scope { get; set; }
    }

    public class Auth0UserProfile
    {
        public string sub { get; set; } = string.Empty;
        public string email { get; set; } = string.Empty;
        public string name { get; set; } = string.Empty;
        public string picture { get; set; } = string.Empty;
    }

    public class Auth0LoginUrlResponse
    {
        public string LoginUrl { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
    }

    public class Auth0LoginUrlRequest
    {
        public string? RedirectUri { get; set; }
        public string? State { get; set; }
        public string? Connection { get; set; }
    }

    public class UserDataPayload
    {
        public string User_Id { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Nickname { get; set; } = string.Empty;
        public string Picture { get; set; } = string.Empty;
        public bool Email_Verified { get; set; }
        public int Login_Count { get; set; }
        public string Last_Login { get; set; } = string.Empty;
        public object? User_Metadata { get; set; }
        public object? App_Metadata { get; set; }
        public string Connection { get; set; } = string.Empty;
        public string Connection_Strategy { get; set; } = string.Empty;
        public string Client_Id { get; set; } = string.Empty;
        public string Client_Name { get; set; } = string.Empty;
    }

    public class Auth0CallbackRequest
    {
        public string Code { get; set; } = string.Empty;
        public string State { get; set; } = string.Empty;
        public string? RedirectUri { get; set; }
    }

    public class Auth0CallbackResponse
    {
        public string AccessToken { get; set; } = string.Empty;
        public string RefreshToken { get; set; } = string.Empty;
        public string TokenType { get; set; } = string.Empty;
        public int ExpiresIn { get; set; }
        public string Scope { get; set; } = string.Empty;
        public UserInfo User { get; set; } = new UserInfo();
    }
}