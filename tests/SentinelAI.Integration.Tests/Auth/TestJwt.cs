using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace SentinelAI.Integration.Tests.Auth;

/// <summary>Mints tokens signed with <see cref="ScanApiFactory"/>'s fixed test key, so
/// tests can exercise the real JWT bearer + role/tenant pipeline end to end. Uses raw
/// short claim names ("sub", "role") to match MapInboundClaims = false.</summary>
internal static class TestJwt
{
    public static string Create(
        Guid tenantId, Guid? userId = null, string? role = null, IEnumerable<string>? scopes = null)
    {
        var claims = new List<Claim> { new("tenant_id", tenantId.ToString()) };

        if (userId is { } id)
            claims.Add(new Claim("sub", id.ToString()));

        if (role is not null)
            claims.Add(new Claim("role", role));

        foreach (var scope in scopes ?? [])
            claims.Add(new Claim("scope", scope));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(ScanApiFactory.JwtSigningKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: ScanApiFactory.JwtIssuer,
            audience: ScanApiFactory.JwtAudience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
