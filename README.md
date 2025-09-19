# Auth Tester

A simple ASP.NET Core Web API for authentication testing with Auth0.

## Environment Setup

This application uses environment variables to store sensitive Auth0 configuration. Follow these steps to set up your environment:

### Development Environment

1. Copy the `.env.example` file to `.env`:

   ```bash
   cp .env.example .env
   ```

2. Update the `.env` file with your Auth0 credentials:
   ```
   AUTH0_DOMAIN=your-actual-domain.auth0.com
   AUTH0_CLIENT_ID=your-actual-client-id
   AUTH0_CLIENT_SECRET=your-actual-client-secret
   AUTH0_AUDIENCE=your-actual-audience
   ```

### Production Environment

For production deployment, set the environment variables in your hosting environment:

- `AUTH0_DOMAIN`
- `AUTH0_CLIENT_ID`
- `AUTH0_CLIENT_SECRET`
- `AUTH0_AUDIENCE`

### Docker Deployment

When using Docker, you can pass environment variables using the `-e` flag or an environment file:

```bash
docker run -e AUTH0_DOMAIN=your-domain.auth0.com \
           -e AUTH0_CLIENT_ID=your-client-id \
           -e AUTH0_CLIENT_SECRET=your-client-secret \
           -e AUTH0_AUDIENCE=your-audience \
           your-app-image
```

Or using an environment file:

```bash
docker run --env-file .env your-app-image
```

## Security Notes

- The `.env` file is included in `.gitignore` and should never be committed to version control
- Use `.env.example` as a template for other developers
- In production, use your hosting platform's environment variable configuration instead of `.env` files
- Ensure environment variables are properly set before running the application

## Running the Application

1. Install dependencies:

   ```bash
   dotnet restore
   ```

2. Set up your `.env` file (see above)

3. Run the application:
   ```bash
   dotnet run
   ```

The application will automatically load environment variables from the `.env` file during startup.
