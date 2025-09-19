# Build stage
FROM mcr.microsoft.com/dotnet/sdk:9.0-alpine AS build
WORKDIR /src

# Copy project file and restore dependencies
COPY auth-tester.csproj .
RUN dotnet restore "auth-tester.csproj"

# Copy source code and build the application
COPY . .
RUN dotnet build "auth-tester.csproj" -c Release -o /app/build

# Publish stage
FROM build AS publish
RUN dotnet publish "auth-tester.csproj" -c Release -o /app/publish --no-restore

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:9.0-alpine AS runtime
WORKDIR /app

# Create a non-root user for security
RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup

# Install necessary packages for production
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    && update-ca-certificates

# Copy published application
COPY --from=publish /app/publish .

# Set ownership to non-root user
RUN chown -R appuser:appgroup /app
USER appuser

# Configure environment variables for production
ENV ASPNETCORE_ENVIRONMENT=Production
ENV ASPNETCORE_URLS=http://+:8080
ENV DOTNET_RUNNING_IN_CONTAINER=true
ENV DOTNET_USE_POLLING_FILE_WATCHER=true

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Entry point
ENTRYPOINT ["dotnet", "auth-tester.dll"]