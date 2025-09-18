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

builder.Services.AddHttpClient("jwks");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.Events = new JwtBearerEvents
        {
            OnMessageReceived = ctx =>
            {
                var headerName = bridge["JwtHeaderName"] ?? "X-Auth-JWT";
                var cookieName = bridge["JwtCookieName"] ?? "AuthJwt";
                if (ctx.Request.Headers.TryGetValue(headerName, out StringValues hv) && !StringValues.IsNullOrEmpty(hv))
                    ctx.Token = hv.FirstOrDefault();
                else if (ctx.Request.Cookies.TryGetValue(cookieName, out var cv) && !string.IsNullOrWhiteSpace(cv))
                    ctx.Token = cv;
                return Task.CompletedTask;
            }
        };

        var validIssuer = jwt["ValidIssuer"];
        var validAudience = jwt["ValidAudience"];
        var jwksUri = jwt["JwksUri"];
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = !string.IsNullOrWhiteSpace(validAudience),
            ValidAudience = string.IsNullOrWhiteSpace(validAudience) ? null : validAudience,
            ValidateIssuer = !string.IsNullOrWhiteSpace(validIssuer),
            ValidIssuer = string.IsNullOrWhiteSpace(validIssuer) ? null : validIssuer,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeyResolver = (t, s, k, p) => JwksCache.Resolve(builder, jwksUri)
        };
    });

builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("CompletedFlow", p => p
        .RequireClaim("bcm:selected_role")
        .RequireClaim("bcm:selected_scheme"));
});

var cookieDomain = publicCookie["Domain"];
var cookieSameSite = publicCookie["SameSite"] ?? "None";
var cookieSecure = bool.TryParse(publicCookie["Secure"], out var sec) ? sec : true;

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
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
        var path = ctx.Request.Path.Value ?? "/";
        var hitsMonolith = !path.StartsWith("/login")
                        && !path.StartsWith("/roles-select")
                        && !path.StartsWith("/schemes-select")
                        && !path.StartsWith("/site-admin")
                        && !path.StartsWith("/ui")
                        && !path.StartsWith("/.well-known");

        if (hitsMonolith)
        {
            var authz = await ctx.RequestServices.GetRequiredService<IAuthorizationService>()
                .AuthorizeAsync(ctx.User, policyName: "CompletedFlow");
            if (!authz.Succeeded)
            {
                await ctx.ChallengeAsync();
                return;
            }

            if (ctx.Request.Cookies.TryGetValue(adminCookieName, out var sid) && !string.IsNullOrEmpty(sid))
            {
                foreach (var h in headerNames) ctx.Request.Headers[h] = sid;
            }
        }

        await next();
    });
});

app.MapReverseProxy();

app.Run();

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
