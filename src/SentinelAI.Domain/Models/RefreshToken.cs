using SentinelAI.Domain.Abstractions;

namespace SentinelAI.Domain.Models
{
    /// <summary>
    /// A long-lived credential that can mint a new short-lived access token without asking
    /// for a password again — and, unlike the access token it renews, can be revoked before
    /// it naturally expires (log out, "log out everywhere", a stolen device).
    /// </summary>
    /// <remarks>
    /// Only the hash is ever stored, the same principle as a password: a database leak
    /// should not hand out working credentials. Rotated on every use — <see cref="RevokedAt"/>
    /// gets set and a new row is issued rather than the same row being reused indefinitely,
    /// so a stolen-but-unused-yet refresh token stops working the moment its legitimate
    /// owner refreshes first.
    /// </remarks>
    public class RefreshToken : ITenantOwned
    {
        public Guid Id { get; set; }
        public Guid TenantId { get; set; }
        public Guid UserId { get; set; }
        public string TokenHash { get; set; } = string.Empty;
        public DateTime ExpiresAt { get; set; }
        public DateTime? RevokedAt { get; set; }
        public DateTime CreatedAt { get; set; }

        public User? User { get; set; }
    }
}
