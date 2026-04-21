---
name: cra-compliance
description: CRA (Cyber Resilience Act) compliance review for .NET projects. Checks code against EU Annex I, Part I, Section 2 requirements including secure defaults, encryption, access control, logging, and attack surface reduction.
origin: ECC
---

# CRA Compliance Review for .NET

Review .NET code against the EU Cyber Resilience Act (CRA) Annex I, Part I, Section 2 requirements. Be direct and specific — point to exact lines, show the fix as a diff.

## When to Activate

- Reviewing code or PRs in .NET projects
- Checking for EU CRA compliance
- Adding authentication, authorization, or encryption
- Configuring middleware pipelines
- Handling user input or database queries
- Setting up logging and monitoring
- Exposing new endpoints

## §2a — No Known Exploitable Vulnerabilities

Scan dependencies and generate an SBOM. CI must fail on known vulnerabilities, not just report them.

```bash
# Check for vulnerable packages
dotnet list package --vulnerable --include-transitive

# Generate SBOM
dotnet CycloneDX <solution> -j -o .
```

## §2b — Secure by Default Configuration

Defaults must fail closed, not open. Don't leak internals to users.

```csharp
// GOOD: default deny
bool isAdmin = false;

// BAD: default allow
bool isAdmin = true;
```

```csharp
// BAD: leaking exception details to the user
catch (Exception ex)
{
    return BadRequest(ex.ToString());
}

// GOOD: log server-side, return generic message
catch (Exception ex)
{
    _logger.LogWarning(ex, "Operation failed");
    return BadRequest("An error occurred");
}
```

## §2c — Vulnerabilities Addressed Through Security Updates

- Use Dependency-Track or similar for continuous monitoring
- Pipeline must include vulnerability scanning as a gate, not just a report

## §2d — Protect Against Unauthorized Access

Set `FallbackPolicy` to `RequireAuthenticatedUser()` so new endpoints are deny-by-default. Don't rely on devs remembering `[Authorize]` — the fallback policy catches the ones they forget.

```csharp
// Program.cs — deny-by-default authorization
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});
```

```csharp
// BAD: no ownership check (IDOR vulnerability)
var order = await db.Orders.FindAsync(orderId);
return Ok(order);

// GOOD: verify resource ownership
var order = await db.Orders.FindAsync(orderId);
var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
if (order.UserId != userId) return Forbid();
return Ok(order);
```

## §2e — Protect Confidentiality (Encryption at Rest and in Transit)

### HTTPS

```csharp
// Program.cs
app.UseHttpsRedirection();
app.UseHsts();
```

### Password Hashing

```csharp
// GOOD: bcrypt with sufficient work factor
var hash = BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);

// BAD: plaintext, MD5, SHA-256 without salt
```

### Secrets Management

```csharp
// BAD: secrets in appsettings.json or source code
"ConnectionStrings": {
    "Default": "Server=prod;Password=hunter2;"
}

// GOOD: injected at runtime via Key Vault, dotnet user-secrets, or environment variables
builder.Configuration.GetConnectionString("Default");
```

## §2f — Protect Data Integrity

No string concatenation in SQL. Use EF Core LINQ or parameterized queries.

```csharp
// BAD: SQL injection via string concatenation
var user = db.Users
    .FromSqlRaw($"SELECT * FROM Users WHERE Id = {userId}")
    .FirstOrDefault();

// GOOD: EF Core LINQ (parameterized automatically)
var user = db.Users
    .Where(u => u.Id == userId)
    .FirstOrDefault();

// GOOD: if raw SQL is needed, use FromSqlInterpolated
var user = db.Users
    .FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {userId}")
    .FirstOrDefault();
```

## §2h — Protect Availability of Essential Functions

```csharp
// Program.cs — rate limiting middleware
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("default", limiter =>
    {
        limiter.PermitLimit = 100;
        limiter.Window = TimeSpan.FromMinutes(1);
    });
});

app.UseRateLimiter();
```

## §2j — Limit Attack Surfaces

No debug endpoints in production. Set security headers via middleware.

```csharp
// Guard debug endpoints
if (app.Environment.IsDevelopment())
{
    app.MapGet("/debug/env", () => Environment.GetEnvironmentVariables());
}
```

```csharp
// Security headers middleware
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["Strict-Transport-Security"] =
        "max-age=31536000; includeSubDomains";
    await next();
});
```

## §2k — Minimize Incident Impact

- Fail closed: if an auth check throws, deny access
- Don't expose stack traces or internal state to users

## §2l — Logging and Monitoring

Log security events with structured logging (Serilog + Seq or similar). NIS2 requires 24-hour early warning on incidents — you need the data to do that.

```csharp
// Security events to log
_logger.LogWarning("Failed login for {Username} from {IP} with {UserAgent}",
    username, HttpContext.Connection.RemoteIpAddress, Request.Headers.UserAgent);

_logger.LogInformation("Successful login for {UserId} from {IP}",
    user.Id, HttpContext.Connection.RemoteIpAddress);

_logger.LogWarning("Authorization failure for {UserId} on {Resource}",
    userId, resourcePath);
```

```csharp
// OpenTelemetry + Prometheus for metrics and alerting
builder.Services.AddOpenTelemetry()
    .WithMetrics(metrics =>
    {
        metrics.AddAspNetCoreInstrumentation();
        metrics.AddPrometheusExporter();
    });
```

## How to Review

When reviewing code, for each file:

1. List which §2 requirements are relevant
2. Flag violations with the specific requirement and a diff showing the fix
3. Note what's already compliant
4. Keep it short — developers stop reading after the first wall of text
