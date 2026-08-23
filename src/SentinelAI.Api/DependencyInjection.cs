using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SentinelAI.Api.Configuration;

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

        // ---- SEC-42/SEC-40: the dashboard is a cross-origin caller ------------------------
        // The Angular UI was written against a same-origin dev proxy, which exists only on a
        // developer's machine. Deployed, the SPA is served from its own host and this API from
        // an Azure Container App, so every read call is cross-origin and the browser refuses it
        // before the request is ever sent. Nothing in this repo's tests or in curl reproduces
        // that — CORS is enforced by the browser alone — so it has to be configured deliberately
        // rather than discovered.
        services.AddCors(options => options.AddPolicy(UiCorsPolicy, policy =>
        {
            // Read inside the delegate for the same reason the JWT options above do: this runs
            // when CorsOptions is first resolved (first request in), by which point every
            // configuration source has been merged — including ones layered on after this
            // method returns, which is how the integration suite supplies its origins.
            //
            // The origin list is an array so a deployment can supply it through environment
            // variables (Cors__AllowedOrigins__0, __1, ...) without a config file, which is all
            // Container Apps gives us.
            var allowedOrigins = configuration.GetSection(CorsAllowedOriginsKey).Get<string[]>() ?? [];

            // A browser's Origin header is scheme+host+port with no trailing slash, and a
            // configured value copied out of a browser address bar almost always has one.
            // WithOrigins compares ordinally, so "https://ui.example.com/" matches nothing and
            // the failure looks identical to having configured no origins at all.
            allowedOrigins = [.. allowedOrigins
                .Where(origin => !string.IsNullOrWhiteSpace(origin))
                .Select(origin => origin.Trim().TrimEnd('/'))];

            // Explicit origins, never AllowAnyOrigin. The UI authenticates with a bearer token,
            // so the policy has to permit credentialed requests, and ASP.NET Core rejects
            // AllowCredentials combined with a wildcard at runtime — as it should, since that
            // pairing lets any site on the internet make authenticated calls on a signed-in
            // user's behalf.
            //
            // An empty list therefore denies every origin rather than allowing all of them.
            // That is the whole point: a deployment that forgets this setting gets a UI that
            // visibly cannot reach the API, which someone fixes in minutes. The convenient
            // fallback — treating "unconfigured" as "allow anything" — turns the same mistake
            // into an API silently open to every origin, with nothing failing to reveal it.
            policy
                .WithOrigins(allowedOrigins)
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        }));

        return services;
    }

    /// <summary>
    /// Configuration key controlling transport security (SEC-35). Defaults to on outside
    /// Development.
    /// </summary>
    public const string RequireHttpsKey = "Security:RequireHttps";

    /// <summary>Port the HTTPS redirect targets. 443 unless the deployment says otherwise.</summary>
    public const string HttpsPortKey = "Security:HttpsPort";

    /// <summary>
    /// Origins the dashboard may call this API from (SEC-42/SEC-40). A string array, so a
    /// deployment supplies it as <c>Cors__AllowedOrigins__0</c>, <c>__1</c>, and so on. Absent
    /// or empty means no cross-origin caller is allowed — see <see cref="UiCorsPolicy"/>.
    /// </summary>
    public const string CorsAllowedOriginsKey = "Cors:AllowedOrigins";

    /// <summary>
    /// The single named CORS policy. Named rather than default so <c>UseCors</c> fails loudly
    /// on a typo instead of quietly applying a policy nobody configured.
    /// </summary>
    public const string UiCorsPolicy = "SentinelAiUi";

    public static WebApplication UseApiServices(this WebApplication app)
    {
        LogSecretSource(app);

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

        // ---- SEC-42/SEC-40: cross-origin access for the dashboard -------------------------
        // Position is the whole of this line's correctness.
        //
        // After the HTTPS block, because a request that is going to be redirected should be
        // redirected, not decorated with headers granting access to a response it will not get.
        //
        // Before UseAuthentication, because a preflight is an unauthenticated OPTIONS request
        // that the browser sends on its own: it carries no Authorization header, by design and
        // with no way for the SPA to add one. Authenticate first and every preflight to a
        // [Authorize]'d endpoint is answered 401 before the CORS middleware can short-circuit
        // it, the browser never issues the real request, and the API looks broken while its
        // logs show only 401s that never had a token to begin with.
        app.UseCors(UiCorsPolicy);

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapControllers();

        return app;
    }

    /// <summary>
    /// Says, once, where this instance's secrets came from (SEC-35, audit 35-A).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The most common way a Key Vault integration is wrong is that it is silently not
    /// running.</b> Nothing throws: the vault is skipped, the committed defaults apply, and the
    /// symptom is an empty signing key or an absent provider credential surfacing somewhere
    /// else entirely. One line at startup turns "we use Key Vault" from a belief into an
    /// observation.
    /// </para>
    /// <para>
    /// A configured vault that loaded <em>zero</em> secrets is called out at warning. It is not
    /// an error — an empty vault is a legitimate state — but it is almost always a permissions
    /// problem on the managed identity, and it looks identical to success everywhere else.
    /// </para>
    /// </remarks>
    private static void LogSecretSource(WebApplication app)
    {
        var result = app.Services.GetService<KeyVaultLoadResult>() ?? KeyVaultLoadResult.NotConfigured;
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("SentinelAI.Secrets");

        if (!result.Enabled)
        {
            logger.LogInformation(
                "No key vault configured ({Key} is empty); secrets come from configuration files, "
                + "environment variables and user-secrets", $"{KeyVaultOptions.SectionName}:Uri");

            return;
        }

        if (result.SecretCount == 0)
        {
            logger.LogWarning(
                "Key vault {Vault} is configured but returned no secrets. The application is "
                + "running on its committed defaults. This is usually a missing 'Key Vault "
                + "Secrets User' role assignment on the managed identity rather than an empty "
                + "vault", result.VaultUri);

            return;
        }

        logger.LogInformation(
            "Secrets loaded from key vault {Vault}: {Count} secret(s), {Aliases} resolved through "
            + "an explicit name mapping, reload {Reload}",
            result.VaultUri,
            result.SecretCount,
            result.AliasCount,
            result.ReloadInterval is { } interval ? $"every {interval.TotalMinutes:0} minute(s)" : "off");
    }
}
