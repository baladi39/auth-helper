# Auth Helper

An ASP.NET Core Web API for authentication testing with Auth0. Includes a browser-friendly landing page with Login and Sign Up buttons, plus a full REST API for programmatic auth flows.

## Getting Started

### Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download)
- An [Auth0](https://auth0.com) application

### 1. Configure Environment

Copy the example env file for your company and fill in your Auth0 credentials:

```bash
cp .env.example .env.flipflop
```

```
AUTH0_DOMAIN=your-auth0-domain.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_AUDIENCE=https://your-auth0-domain.auth0.com/api/v2/
```

Multiple company configurations are supported (e.g. `.env.flipflop`, `.env.saascertain`).

### 2. Configure Auth0 Callback URLs

In your Auth0 Application Settings, add the following to **Allowed Callback URLs**:

```
http://localhost:5018/api/Auth/callback
```

### 3. Run the Application

```bash
dotnet restore
dotnet run --project AuthHelper.csproj -- --company flipflop
```

To run with a different company config:

```bash
dotnet run --project AuthHelper.csproj -- --company saascertain
```

The app starts at `http://localhost:5018`.

## Usage

### Landing Page

Open `http://localhost:5018` in your browser. You'll see two buttons:

- **Log In** -- redirects to Auth0's Universal Login
- **Sign Up** -- redirects to Auth0's Universal Login with the sign-up screen

After authentication, Auth0 redirects back to `/api/Auth/callback` which returns the tokens.

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Landing page with Login/Sign Up buttons |
| `GET` | `/api/Auth/login` | Redirects to Auth0 login UI |
| `POST` | `/api/Auth/login` | Authenticate with email/password (API) |
| `POST` | `/api/Auth/signup` | Register a new user (API) |
| `POST` | `/api/Auth/login-url` | Get Auth0 login URL as JSON |
| `GET` | `/api/Auth/callback` | Auth0 callback handler |
| `GET` | `/api/Auth/me` | Get current user info (requires Bearer token) |
| `POST` | `/api/Auth/receive-user-data` | Receive user data payload |
| `GET` | `/api/Auth/health` | Auth service health check |
| `GET` | `/health` | App health check |

### Query Parameters for `GET /api/Auth/login`

| Parameter | Default | Description |
|-----------|---------|-------------|
| `redirectUri` | `http://localhost:5018/api/Auth/callback` | Where Auth0 redirects after login |
| `state` | `my-custom-state` | CSRF state parameter |
| `connection` | `Username-Password-Authentication` | Auth0 connection type |
| `screen_hint` | _(none)_ | Set to `signup` to open the sign-up form |

### Swagger

API documentation is available at `/swagger` when running in Development mode.

## Docker

```bash
docker run --env-file .env.flipflop your-app-image
```

Or pass variables individually:

```bash
docker run -e AUTH0_DOMAIN=your-domain.auth0.com \
           -e AUTH0_CLIENT_ID=your-client-id \
           -e AUTH0_CLIENT_SECRET=your-client-secret \
           -e AUTH0_AUDIENCE=your-audience \
           your-app-image
```

## Security Notes

- `.env` files are in `.gitignore` and should never be committed
- Use `.env.example` as a template for other developers
- In production, use your hosting platform's environment variable configuration
