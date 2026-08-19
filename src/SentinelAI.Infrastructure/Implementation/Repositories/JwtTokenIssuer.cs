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
        var signingKey = _jwt["SigningKey"];
        if (string.IsNullOrEmpty(signingKey))
            throw new InvalidOperationException("Authentication:Jwt:SigningKey is not configured.");

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

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

    public string GenerateRefreshToken() =>
        // Opaque and random - not a JWT, carries no claims. Base64url so it's safe to put
        // straight into a URL or a header with no extra escaping.
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(64))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public string HashRefreshToken(string rawToken) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));

    private double ParseOrDefault(string key, double defaultValue)
    {
        var raw = _jwt[key];
        return string.IsNullOrEmpty(raw) ? defaultValue : double.Parse(raw);
    }
}
