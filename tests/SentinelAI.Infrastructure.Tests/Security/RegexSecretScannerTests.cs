using SentinelAI.Infrastructure.Security;

namespace SentinelAI.Infrastructure.Tests.Security;

/// <summary>
/// SEC-33, the detector. Two properties carry the ticket: a credential in received content is
/// found and removed, and the plaintext is never returned in any form.
/// </summary>
public class RegexSecretScannerTests
{
    private static readonly RegexSecretScanner Scanner = new();

    [Theory]
    // Shaped — the issuer's own format.
    [InlineData("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", "aws-access-key-id")]
    [InlineData("token: ghp_1234567890abcdefghijklmnopqrstuvwxyz", "ghp_1234567890abcdefghijklmnopqrstuvwxyz", "github-token")]
    [InlineData("key = AIzaSyD-1234567890abcdefghijklmnopqrstu", "AIzaSyD-1234567890abcdefghijklmnopqrstu", "google-api-key")]
    [InlineData("slack = xoxb-12345678901-abcdefg", "xoxb-12345678901-abcdefg", "slack-token")]
    [InlineData("db = postgres://app:s3cr3tpw@db.internal:5432/orders", "s3cr3tpw", "url-embedded-password")]
    // Assignment — a value the neighbouring word identifies as a credential.
    [InlineData("ENV ORDER_SVC_API_KEY=\"demo-fixture-dummy-key-not-real-000111\"", "demo-fixture-dummy-key-not-real-000111", "assigned-secret")]
    [InlineData("Server=db;Password=Sup3rS3cret!;", "Sup3rS3cret!", "connection-string-password")]
    [InlineData("Authorization: Bearer abcdefghij0123456789", "abcdefghij0123456789", "bearer-token")]
    public void Finds_and_removes_the_credential(string input, string secret, string expectedRule)
    {
        var result = Scanner.Scan(input);

        Assert.True(result.HasSecrets);
        Assert.Contains(expectedRule, result.Matches.Select(m => m.RuleId));

        // The point of the whole ticket: the value is gone from the text that travels on.
        Assert.DoesNotContain(secret, result.Redacted, StringComparison.Ordinal);
        Assert.Contains("[REDACTED:", result.Redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Finds_a_private_key_block_whole()
    {
        var pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Fq\nabc123\n-----END RSA PRIVATE KEY-----";

        var result = Scanner.Scan($"resource \"tls\" {{\n  key = <<EOT\n{pem}\nEOT\n}}");

        Assert.Contains("private-key", result.Matches.Select(m => m.RuleId));
        Assert.DoesNotContain("MIIEowIBAAKCAQEAx7Fq", result.Redacted, StringComparison.Ordinal);
    }

    [Theory]
    // Terraform references are the noise case: they appear in nearly every real .tf file and
    // are evidence the author did the right thing, not a finding.
    [InlineData("password = var.db_password")]
    [InlineData("api_key = \"${var.order_api_key}\"")]
    [InlineData("client_secret = local.secret_ref")]
    [InlineData("token = data.aws_secretsmanager_secret_version.app.secret_string")]
    [InlineData("password = \"\"")]
    [InlineData("api_key = <your-key-here>")]
    [InlineData("password = changeme")]
    public void Leaves_a_placeholder_or_reference_alone(string input)
    {
        var result = Scanner.Scan(input);

        Assert.False(result.HasSecrets);
        Assert.Equal(input, result.Redacted);
    }

    [Fact]
    public void Reports_the_line_a_secret_sits_on()
    {
        var text = "FROM base\nWORKDIR /app\nENV APP_API_KEY=\"abcdef1234567890\"\nEXPOSE 8080";

        var match = Assert.Single(Scanner.Scan(text).Matches);

        Assert.Equal(3, match.Line);
    }

    [Fact]
    public void Redacts_once_when_two_rules_match_the_same_value()
    {
        // A bearer JWT trips both the shaped jwt rule and the bearer-token rule. Nesting the
        // placeholders would misreport one secret as two.
        var jwt = "eyJhbGciOi.eyJzdWIiOjEyMw.SflKxwRJSMeKKF2QT4";

        var result = Scanner.Scan($"Authorization: Bearer {jwt}");

        Assert.Single(result.Matches);
        Assert.DoesNotContain(jwt, result.Redacted, StringComparison.Ordinal);
        Assert.DoesNotContain("[REDACTED:[", result.Redacted, StringComparison.Ordinal);
    }

    [Fact]
    public void Leaves_ordinary_prose_untouched()
    {
        // Scanner messages are the highest-volume input to this thing. If it fires on them the
        // findings become unreadable, so the no-op case is a real requirement.
        const string message = "Unsafe deserialization in OrderService: TypeNameHandling.All "
            + "allows an attacker to instantiate arbitrary types (CWE-502).";

        var result = Scanner.Scan(message);

        Assert.False(result.HasSecrets);
        Assert.Equal(message, result.Redacted);
    }

    [Fact]
    public void Treats_empty_and_null_as_clean()
    {
        Assert.False(Scanner.Scan(null).HasSecrets);
        Assert.False(Scanner.Scan("").HasSecrets);
        Assert.Equal(string.Empty, Scanner.Scan(null).Redacted);
    }

    [Fact]
    public void Never_hands_back_the_plaintext_it_found()
    {
        // The contract's one structural guarantee: SecretMatch has no value field, so a caller
        // logging every match cannot leak a credential. Asserted here so removing that
        // property from the record breaks a test rather than a customer.
        var result = Scanner.Scan("aws_access_key_id = AKIAIOSFODNN7EXAMPLE");

        Assert.All(result.Matches, m =>
            Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", m.ToString(), StringComparison.Ordinal));
    }
}
