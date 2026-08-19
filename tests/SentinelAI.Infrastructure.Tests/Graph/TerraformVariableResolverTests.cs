using SentinelAI.Infrastructure.Graph;

namespace SentinelAI.Infrastructure.Tests.Graph;

/// <summary>SEC-19, infra side, step 1: resolving Terraform <c>variable</c> defaults and
/// <c>locals</c>, and substituting both interpolated and bare references.</summary>
public class TerraformVariableResolverTests
{
    private const string Tf = """
        variable "order_image" {
          type    = string
          default = "tinyapp/order"
        }

        locals {
          order_image_tag = "tinyapp/order:latest"
        }
        """;

    [Fact]
    public void Reads_variable_defaults_and_locals()
    {
        var variables = TerraformVariableResolver.Resolve(new Dictionary<string, string> { ["main.tf"] = Tf });

        Assert.Equal("tinyapp/order", variables.Variables["order_image"]);
        Assert.Equal("tinyapp/order:latest", variables.Locals["order_image_tag"]);
    }

    [Fact]
    public void Substitutes_an_interpolated_variable_reference()
    {
        var variables = TerraformVariableResolver.Resolve(new Dictionary<string, string> { ["main.tf"] = Tf });

        var (text, resolved) = TerraformVariableResolver.Substitute("${var.order_image}", variables);

        Assert.Equal("tinyapp/order", text);
        Assert.True(resolved);
    }

    [Fact]
    public void Substitutes_a_bare_local_reference()
    {
        var variables = TerraformVariableResolver.Resolve(new Dictionary<string, string> { ["main.tf"] = Tf });

        var (text, resolved) = TerraformVariableResolver.Substitute("local.order_image_tag", variables);

        Assert.Equal("tinyapp/order:latest", text);
        Assert.True(resolved);
    }

    [Fact]
    public void An_already_literal_string_is_left_untouched_and_reports_no_resolution()
    {
        var variables = TerraformVariableResolver.Resolve(new Dictionary<string, string> { ["main.tf"] = Tf });

        var (text, resolved) = TerraformVariableResolver.Substitute("tinyapp/order:latest", variables);

        Assert.Equal("tinyapp/order:latest", text);
        Assert.False(resolved);
    }

    [Fact]
    public void An_unknown_variable_reference_is_left_as_its_source_text()
    {
        var variables = TerraformVariableResolver.Resolve(new Dictionary<string, string> { ["main.tf"] = Tf });

        var (text, resolved) = TerraformVariableResolver.Substitute("${var.does_not_exist}", variables);

        Assert.Equal("var.does_not_exist", text);
        Assert.False(resolved);
    }
}
