# Chirpy

> This project is part of the [Learn HTTP Servers in Go](https://boot.dev/learn/learn-http-servers) course from boot.dev. The code can be better organized but actually, i don't care.

A simple HTTP server built with Go that implements a basic social media API for creating and managing "chirps" (short messages) and users.

## Features

- **Chirps API**: Create, read, and manage short messages (140 character limit)
- **Users API**: User registration and management
- **Content Filtering**: Automatic profanity filtering for chirps
- **Metrics**: Hit counter and admin dashboard
- **Database**: PostgreSQL integration with SQLC for type-safe queries
- **Health Checks**: Readiness endpoints for monitoring

## API Endpoints

### Chirps

- `POST /api/chirps` - Create a new chirp
- `GET /api/chirps` - Get all chirps
- `GET /api/chirps/{id}` - Get a specific chirp

### Users

- `POST /api/users` - Create a new user

### System

- `GET /healthz` - Health check
- `GET /metrics` - Hit counter metrics
- `GET /admin/metrics` - Admin dashboard
- `POST /reset` - Reset metrics and data (dev only)

## Getting Started

1. **Prerequisites**
   - Go 1.23.2+
   - PostgreSQL database

2. **Environment Setup**

   ```bash
   # Create .env file
   echo "DB_URL=postgres://username:password@localhost/dbname?sslmode=disable" > .env
   echo "PLATFORM=dev" >> .env
   ```

3. **Database Setup**

   ```bash
   # Run migrations
   goose -dir migrations postgres "your-db-url" up
   ```

4. **Run the server**

   ```bash
   go run main.go
   ```

The server will start on `:8080` and serve a simple web interface at `/app/`.

## Project Structure

```
├── main.go              # Main server implementation
├── internal/database/    # Database models and queries
├── migrations/          # Database migrations
├── queries/             # SQLC query definitions
└── assets/              # Static assets
```
