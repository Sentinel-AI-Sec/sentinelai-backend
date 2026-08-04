using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace SentinelAI.Api;

public static class DependencyInjection
{
    public static IServiceCollection AddApiServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddControllers();

        // Bearer-token auth for machine callers (the GitHub Action's scan:write token).
        // Placeholder until SEC-26 lands a real identity provider: a single symmetric
        // signing key, configured per environment and never committed. HttpCallerContext
        // is what actually reads the resulting claims.
        var jwt = configuration.GetSection("Authentication:Jwt");

        services
            .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                // JwtSecurityTokenHandler otherwise silently remaps short claim names to
                // long legacy URIs on the way in ("role" -> ClaimTypes.Role, "sub" ->
                // ClaimTypes.NameIdentifier), which would quietly override RoleClaimType
                // below and break every role check. Keep claims exactly as issued and read
                // them by their raw names everywhere (HttpCallerContext does the same).
                options.MapInboundClaims = false;

                // Read inside the delegate, not above it: this delegate runs lazily (first
                // time the auth handler resolves its options), by which point every
                // configuration source — including anything layered on after this method
                // returns, e.g. test overrides — has been merged in. Reading eagerly here
                // would snapshot whatever "Authentication:Jwt" looked like at host-startup
                // time and silently ignore anything added later.
                var signingKey = jwt["SigningKey"];

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwt["Issuer"],
                    ValidateAudience = true,
                    ValidAudience = jwt["Audience"],
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = string.IsNullOrEmpty(signingKey)
                        ? null
                        : new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
                    // SEC-32: RBAC reads this claim. [Authorize(Roles = "admin")] and
                    // HttpCallerContext.Role both key off "role" — a machine token that
                    // never carries it can never satisfy a role-gated endpoint.
                    RoleClaimType = "role",
                };
            });

        services.AddAuthorization();

        return services;
    }

    public static WebApplication UseApiServices(this WebApplication app)
    {
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        return app;
    }
}
