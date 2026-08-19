using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>SEC-19, step 3: stripping registry prefixes and tags so two image references can be
/// compared by bare repository name alone.</summary>
public class ImageNameNormalizerTests
{
    [Theory]
    [InlineData("tinyapp/order", "tinyapp/order")]
    [InlineData("123456789.dkr.ecr.us-east-1.amazonaws.com/tinyapp/order:latest", "tinyapp/order")]
    [InlineData("123456789.dkr.ecr.us-east-1.amazonaws.com/tinyapp/order", "tinyapp/order")]
    [InlineData("tinyapp/order:v1.2.3", "tinyapp/order")]
    [InlineData("registry.internal:5000/tinyapp/order:latest", "tinyapp/order")]
    [InlineData("TinyApp/Order", "tinyapp/order")]
    [InlineData("tinyapp/order@sha256:abcdef1234567890", "tinyapp/order")]
    public void Normalizes_to_the_bare_lowercase_repository_name(string input, string expected)
    {
        Assert.Equal(expected, ImageNameNormalizer.Normalize(input));
    }

    [Fact]
    public void A_bare_repo_name_with_no_dot_or_colon_first_segment_is_not_mistaken_for_a_registry()
    {
        // "tinyapp" has neither '.' nor ':' — must survive as part of the repo name, not be
        // stripped as if it were a registry host.
        Assert.Equal("tinyapp/order", ImageNameNormalizer.Normalize("tinyapp/order"));
    }
}
