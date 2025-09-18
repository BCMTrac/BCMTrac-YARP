using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json;
using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

var jwt = builder.Configuration.GetSection("JWT");
var bridge = builder.Configuration.GetSection("Bridge");
var publicCookie = builder.Configuration.GetSection("PublicCookie");

// Temporarily disable JWT validation for basic routing test
// Will re-enable once routing is confirmed working
builder.Services.AddHttpClient("jwks", client =>
{
    client.Timeout = TimeSpan.FromSeconds(30);
}).ConfigurePrimaryHttpMessageHandler(() =>
{
    var handler = new HttpClientHandler();
    if (builder.Environment.IsDevelopment())
    {
        handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
    }
    return handler;
});

// Basic auth setup without JWT validation for now
builder.Services.AddAuthentication("NoOp")
    .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, NoOpAuthHandler>("NoOp", _ => { });

builder.Services.AddAuthorization();

var cookieDomain = publicCookie["Domain"];
var cookieSameSite = publicCookie["SameSite"] ?? "None";
var cookieSecure = bool.TryParse(publicCookie["Secure"], out var sec) ? sec : true;

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .ConfigureHttpClient((context, handler) =>
    {
        // Skip certificate validation in development for all proxy destinations
        if (builder.Environment.IsDevelopment())
        {
            handler.SslOptions.RemoteCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) => true;
        }
    })
    .AddTransforms(builderContext =>
    {
        builderContext.AddResponseTransform(ctx =>
        {
            if (ctx.ProxyResponse is null) return default;
            if (!ctx.ProxyResponse.Headers.TryGetValues("Set-Cookie", out var setCookies)) return default;
            var rewritten = new List<string>();
            foreach (var sc in setCookies)
            {
                var s = sc;
                if (!string.IsNullOrWhiteSpace(cookieDomain))
                {
                    if (s.Contains("Domain=", StringComparison.OrdinalIgnoreCase))
                        s = System.Text.RegularExpressions.Regex.Replace(s, "Domain=[^;]*", $"Domain={cookieDomain}", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                    else s += $"; Domain={cookieDomain}";
                }
                if (cookieSecure && !s.Contains("Secure", StringComparison.OrdinalIgnoreCase)) s += "; Secure";
                if (s.Contains("SameSite=", StringComparison.OrdinalIgnoreCase))
                    s = System.Text.RegularExpressions.Regex.Replace(s, "SameSite=[^;]*", $"SameSite={cookieSameSite}", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                else s += $"; SameSite={cookieSameSite}";
                rewritten.Add(s);
            }
            ctx.HttpContext.Response.Headers.Remove("Set-Cookie");
            foreach (var s in rewritten) ctx.HttpContext.Response.Headers.Append("Set-Cookie", s);
            return default;
        });
    });

var app = builder.Build();

// Early health check short-circuit
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path.Value ?? string.Empty;
    if (string.Equals(path, "/health", StringComparison.Ordinal))
    {
        ctx.Response.ContentType = "application/json";
        await ctx.Response.WriteAsync("{\"ok\":true}");
        return;
    }
    await next();
});

app.UseForwardedHeaders(new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
});

app.UseHttpsRedirection();
app.UseHsts();

var adminCookieName = bridge["AdminBackOfficeCookieName"] ?? "AdminBackOffcieCookie";
var headerNames = bridge.GetSection("HeaderNames").Get<string[]>() ?? new[] { "X-Session-Id", "X-SessionID", "X-Legacy-Session-3" };

app.UseWhen(ctx => !ctx.Request.Path.StartsWithSegments("/health"), branch =>
{
    branch.UseAuthentication();
    branch.UseAuthorization();

    branch.Use(async (ctx, next) =>
    {
        // Temporarily bypass authorization for testing - just forward headers
        if (ctx.Request.Cookies.TryGetValue(adminCookieName, out var sid) && !string.IsNullOrEmpty(sid))
        {
            foreach (var h in headerNames) ctx.Request.Headers[h] = sid;
        }
        await next();
    });
});

app.MapReverseProxy();

app.Run();

// Temporary no-op auth handler for testing
public class NoOpAuthHandler : Microsoft.AspNetCore.Authentication.AuthenticationHandler<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions>
{
    public NoOpAuthHandler(Microsoft.Extensions.Options.IOptionsMonitor<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions> options, 
        Microsoft.Extensions.Logging.ILoggerFactory logger, System.Text.Encodings.Web.UrlEncoder encoder) 
        : base(options, logger, encoder) { }

    protected override Task<Microsoft.AspNetCore.Authentication.AuthenticateResult> HandleAuthenticateAsync()
    {
        var identity = new System.Security.Claims.ClaimsIdentity("NoOp");
        var principal = new System.Security.Claims.ClaimsPrincipal(identity);
        var ticket = new Microsoft.AspNetCore.Authentication.AuthenticationTicket(principal, "NoOp");
        return Task.FromResult(Microsoft.AspNetCore.Authentication.AuthenticateResult.Success(ticket));
    }
}

internal static class JwksCache
{
    private static readonly object _lock = new();
    private static DateTimeOffset _expiry = DateTimeOffset.MinValue;
    private static List<SecurityKey>? _cache;

    public static IReadOnlyCollection<SecurityKey> Resolve(WebApplicationBuilder builder, string? jwksUri)
    {
        if (string.IsNullOrWhiteSpace(jwksUri)) return Array.Empty<SecurityKey>();
        var now = DateTimeOffset.UtcNow;
        lock (_lock)
        {
            if (_cache != null && now < _expiry) return _cache;
        }
        try
        {
            using var scope = builder.Services.BuildServiceProvider().CreateScope();
            var factory = scope.ServiceProvider.GetRequiredService<IHttpClientFactory>();
            var client = factory.CreateClient("jwks");
            var json = client.GetStringAsync(jwksUri).GetAwaiter().GetResult();
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("keys", out var keysEl)) return Array.Empty<SecurityKey>();
            var set = new List<SecurityKey>();
            foreach (var el in keysEl.EnumerateArray()) set.Add(new JsonWebKey(el.GetRawText()));
            lock (_lock)
            {
                _cache = set;
                _expiry = now.AddMinutes(5);
            }
            return set;
        }
        catch
        {
            return _cache ?? (IReadOnlyCollection<SecurityKey>)Array.Empty<SecurityKey>();
        }
    }
}
