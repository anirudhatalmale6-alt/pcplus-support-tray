using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using PCPlus.Dashboard.Data;
using PCPlus.Dashboard.Services;

var builder = WebApplication.CreateBuilder(args);

// SQLite database (easy deployment, no external DB needed)
var dataDir = Path.Combine(AppContext.BaseDirectory, "data");
Directory.CreateDirectory(dataDir);
var dbPath = Path.Combine(dataDir, "dashboard.db");

builder.Services.AddDbContext<DashboardDb>(options =>
    options.UseSqlite($"Data Source={dbPath}"));

builder.Services.AddControllers();
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
});

// Cookie authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login.html";
        options.LogoutPath = "/api/auth/logout";
        options.ExpireTimeSpan = TimeSpan.FromDays(7);
        options.SlidingExpiration = true;
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Events.OnRedirectToLogin = context =>
        {
            // Return 401 for API calls, redirect for page requests
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                context.Response.StatusCode = 401;
                return Task.CompletedTask;
            }
            context.Response.Redirect(context.RedirectUri);
            return Task.CompletedTask;
        };
    });
builder.Services.AddAuthorization();

// Background services
builder.Services.AddSingleton<ReportGenerator>();
builder.Services.AddHostedService<EmailReportService>();

var app = builder.Build();

// Auto-create/migrate database on startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<DashboardDb>();
    db.Database.EnsureCreated();

    // Add new columns if missing (EnsureCreated doesn't alter existing tables)
    try { db.Database.ExecuteSqlRaw("ALTER TABLE Devices ADD COLUMN GpuTempC REAL NOT NULL DEFAULT 0"); } catch { }
    try { db.Database.ExecuteSqlRaw("ALTER TABLE Devices ADD COLUMN LocalIp TEXT NOT NULL DEFAULT ''"); } catch { }
    try { db.Database.ExecuteSqlRaw("ALTER TABLE Devices ADD COLUMN PublicIp TEXT NOT NULL DEFAULT ''"); } catch { }
    try { db.Database.ExecuteSqlRaw("ALTER TABLE Devices ADD COLUMN BitLockerKeysJson TEXT NOT NULL DEFAULT '[]'"); } catch { }
    try { db.Database.ExecuteSqlRaw("ALTER TABLE Devices ADD COLUMN StorageDrivesJson TEXT NOT NULL DEFAULT '[]'"); } catch { }
    try { db.Database.ExecuteSqlRaw("ALTER TABLE Devices ADD COLUMN MacAddress TEXT NOT NULL DEFAULT ''"); } catch { }
    try { db.Database.ExecuteSqlRaw("ALTER TABLE Devices ADD COLUMN NetworkUpMbps REAL NOT NULL DEFAULT 0"); } catch { }
    try { db.Database.ExecuteSqlRaw("ALTER TABLE Devices ADD COLUMN NetworkDownMbps REAL NOT NULL DEFAULT 0"); } catch { }
    try { db.Database.ExecuteSqlRaw(@"CREATE TABLE IF NOT EXISTS EmailSchedules (
        Id INTEGER PRIMARY KEY AUTOINCREMENT,
        CustomerName TEXT NOT NULL DEFAULT '',
        RecipientEmails TEXT NOT NULL DEFAULT '',
        Frequency TEXT NOT NULL DEFAULT 'weekly',
        DayOfWeek INTEGER NOT NULL DEFAULT 1,
        Hour INTEGER NOT NULL DEFAULT 8,
        Enabled INTEGER NOT NULL DEFAULT 1,
        LastSentAt TEXT,
        NextSendAt TEXT,
        CreatedAt TEXT NOT NULL DEFAULT (datetime('now')),
        CreatedBy TEXT NOT NULL DEFAULT ''
    )"); } catch { }
    try { db.Database.ExecuteSqlRaw(@"CREATE TABLE IF NOT EXISTS SmtpConfigs (
        Id INTEGER PRIMARY KEY AUTOINCREMENT,
        Host TEXT NOT NULL DEFAULT '',
        Port INTEGER NOT NULL DEFAULT 587,
        Username TEXT NOT NULL DEFAULT '',
        Password TEXT NOT NULL DEFAULT '',
        FromAddress TEXT NOT NULL DEFAULT '',
        FromName TEXT NOT NULL DEFAULT 'PC Plus Computing',
        UseSsl INTEGER NOT NULL DEFAULT 1
    )"); } catch { }
}

app.UseCors();
app.UseAuthentication();
app.UseAuthorization();
app.UseStaticFiles();
app.MapControllers();

// Serve the dashboard SPA - fallback to index.html (requires auth)
app.MapFallbackToFile("index.html").RequireAuthorization();

app.Run();
