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

        // ---- SEC-35: encryption in transit -----------------------------------------------
        // The port is set explicitly because UseHttpsRedirection does nothing at all when it
        // cannot work one out — it logs a warning and passes the request through in the clear.
        // Behind a reverse proxy that terminates TLS (which is how this is deployed) there is
        // no HTTPS port for it to find, so leaving this unset means transport security appears
        // configured and silently is not.
        services.AddHttpsRedirection(options =>
            options.HttpsPort = configuration.GetValue(HttpsPortKey, 443));

        return services;
    }

    /// <summary>
    /// Configuration key controlling transport security (SEC-35). Defaults to on outside
    /// Development.
    /// </summary>
    public const string RequireHttpsKey = "Security:RequireHttps";

    /// <summary>Port the HTTPS redirect targets. 443 unless the deployment says otherwise.</summary>
    public const string HttpsPortKey = "Security:HttpsPort";

    public static WebApplication UseApiServices(this WebApplication app)
    {
        // ---- SEC-35: encryption in transit ------------------------------------------------
        // A scan bundle carries a customer's infrastructure configuration and a bearer token
        // rides on every request; both are readable by anyone on the path if this is off.
        //
        // It is a setting rather than a hard-coded call so the behaviour is testable. Wiring
        // UseHttpsRedirection unconditionally would 307 every request in the integration suite,
        // and the usual fix — an IsDevelopment() guard — makes the redirect impossible to test
        // at all, which is how transport security ends up unverified. Default on outside
        // Development; a test can switch it on explicitly and assert the redirect really fires.
        var requireHttps = app.Configuration.GetValue(RequireHttpsKey, !app.Environment.IsDevelopment());

        if (requireHttps)
        {
            // Tells the browser to use HTTPS next time, so only the very first request is
            // exposed. Ordered before the redirect deliberately: a response that redirects
            // should still carry the header that prevents the next redirect being needed.
            app.UseHsts();
            app.UseHttpsRedirection();
        }

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        return app;
    }
}
