using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

/// <summary>
/// Signs access tokens with the same key, issuer and audience the Api layer validates
/// against (<c>Authentication:Jwt:*</c>) — issuing and validating are two sides of the same
/// configuration, so they read the same section rather than each having their own copy.
/// </summary>
public sealed class JwtTokenIssuer(IConfiguration configuration) : IJwtTokenIssuer
{
    private readonly IConfigurationSection _jwt = configuration.GetSection("Authentication:Jwt");

    public TimeSpan AccessTokenLifetime => TimeSpan.FromMinutes(ParseOrDefault("AccessTokenMinutes", 60));

    public TimeSpan RefreshTokenLifetime => TimeSpan.FromDays(ParseOrDefault("RefreshTokenDays", 30));

    public string IssueAccessToken(User user)
    {
        var credentials = CreateSigningCredentials();

        // Raw, short claim names throughout - matches MapInboundClaims = false on the
        // validation side (Api/DependencyInjection.cs). Nothing here should ever get
        // rewritten in transit.
        var claims = new List<Claim>
        {
            new("sub", user.Id.ToString()),
            new("tenant_id", user.TenantId.ToString()),
            new("role", user.Role),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        // One space-delimited OAuth "scope" claim, which HttpCallerContext splits. Without it
        // every HasScope check fails for every human user — see RoleScopes for how that went
        // unnoticed. Machine tokens are issued elsewhere and carry their own scopes.
        if (RoleScopes.ClaimValue(user.Role) is { } scopes)
            claims.Add(new Claim("scope", scopes));

        var token = new JwtSecurityToken(
            issuer: _jwt["Issuer"],
            audience: _jwt["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.Add(AccessTokenLifetime),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public TimeSpan MachineTokenLifetime => TimeSpan.FromDays(ParseOrDefault("MachineTokenDays", 365));

    public string IssueMachineToken(Guid tenantId, IReadOnlyList<string> scopes)
    {
        var credentials = CreateSigningCredentials();

        // tenant_id and scope, and nothing else that grants anything. No "sub" - a CI run is not
        // a person, and HttpCallerContext.UserId answering null for this token is what the rest
        // of the codebase already expects. No "role" - see IJwtTokenIssuer.IssueMachineToken.
        var claims = new List<Claim>
        {
            new("tenant_id", tenantId.ToString()),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

        // One space-delimited claim, the same shape IssueAccessToken writes and the same shape
        // HttpCallerContext.HasScope splits. Absent rather than empty when nothing was granted.
        if (scopes.Count > 0)
            claims.Add(new Claim("scope", string.Join(' ', scopes)));

        var token = new JwtSecurityToken(
            issuer: _jwt["Issuer"],
            audience: _jwt["Audience"],
            claims: claims,
            expires: DateTime.UtcNow.Add(MachineTokenLifetime),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public string GenerateRefreshToken() =>
        // Opaque and random - not a JWT, carries no claims. Base64url so it's safe to put
        // straight into a URL or a header with no extra escaping.
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public string HashRefreshToken(string rawToken) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));

    /// <summary>
    /// The one place the signing key is read. Both token kinds have to be signed with the key the
    /// Api layer validates against, so there is deliberately not a second copy of this to drift.
    /// </summary>
    private SigningCredentials CreateSigningCredentials()
    {
        var signingKey = _jwt["SigningKey"];
        if (string.IsNullOrEmpty(signingKey))
            throw new InvalidOperationException("Authentication:Jwt:SigningKey is not configured.");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
        return new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    }

    private double ParseOrDefault(string key, double defaultValue)
    {
        var raw = _jwt[key];
        return string.IsNullOrEmpty(raw) ? defaultValue : double.Parse(raw);
    }
}
