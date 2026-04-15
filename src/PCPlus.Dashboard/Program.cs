using Microsoft.EntityFrameworkCore;
using PCPlus.Dashboard.Data;

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

var app = builder.Build();

// Auto-create/migrate database on startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<DashboardDb>();
    db.Database.EnsureCreated();
}

app.UseCors();
app.UseStaticFiles();
app.MapControllers();

// Serve the dashboard SPA - fallback to index.html
app.MapFallbackToFile("index.html");

app.Run();
