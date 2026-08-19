using System.Reflection;
using Microsoft.Extensions.AI;
using SentinelAI.Infrastructure.Agents.Orchestration;
using SentinelAI.Infrastructure.Agents.Providers;

namespace SentinelAI.Integration.Tests.Agents;

/// <summary>
/// SEC-30 step 3: <em>"Ensure no agent code references a specific provider directly."</em>
/// </summary>
/// <remarks>
/// <para>
/// This holds today by discipline. Nothing enforces it, and it is the kind of rule that decays
/// quietly — one <c>if (provider == ModelProvider.Anthropic)</c> added inside an executor to
/// work around a vendor quirk, and the abstraction is over: switching provider is no longer a
/// config change, and the only symptom is that the other provider starts behaving oddly.
/// </para>
/// <para>
/// The rule is deliberately narrower than "the agents may not reference the Providers
/// namespace". They must reference <see cref="IChatClientFactory"/> — that <em>is</em> the
/// abstraction. What they may not know is what the factory builds. So the workflow may know a
/// factory exists; it may not know that Anthropic does.
/// </para>
/// <para>
/// What this checks is the type <em>surface</em>: base types, interfaces, fields, properties,
/// constructor and method signatures, generic arguments, and method local variables. That
/// covers every realistic way an executor could reach a provider, because to compare against
/// <see cref="ModelProvider"/> it must first hold a <see cref="ModelProviderOptions"/> or
/// receive one. It would not catch a comparison built entirely from constants inlined by the
/// compiler — <see cref="The_guard_detects_a_violation"/> exists so the guard's own reach is
/// demonstrated rather than assumed.
/// </para>
/// </remarks>
public class ProviderIsolationTests
{
    /// <summary>The namespaces that must stay provider-blind.</summary>
    private static readonly string[] AgentNamespaces =
    [
        "SentinelAI.Infrastructure.Agents.Executors",
        "SentinelAI.Infrastructure.Agents.Orchestration",
    ];

    /// <summary>
    /// Types that name one vendor, or that decide between vendors. Referencing any of them
    /// from agent code is the violation.
    /// </summary>
    private static readonly Type[] ProviderSpecificTypes =
    [
        typeof(ModelProvider),
        typeof(ModelProviderOptions),
        typeof(AgentModelOptions),
        typeof(ScriptedChatClient),
    ];

    /// <summary>Vendor SDK namespaces. No agent type may name a type from one.</summary>
    private static readonly string[] VendorNamespaceRoots = ["OpenAI", "Azure", "Anthropic"];

    [Fact]
    public void No_agent_type_references_a_specific_provider()
    {
        var offenders = AgentTypes()
            .SelectMany(agentType => Surface(agentType)
                .Where(IsProviderSpecific)
                .Select(referenced => $"{agentType.Name} references {referenced.FullName}"))
            .Distinct()
            .ToList();

        Assert.Empty(offenders);
    }

    /// <summary>
    /// The abstraction the agents <em>are</em> allowed to know about — asserted so the test
    /// above cannot pass by the agent namespaces having quietly become empty.
    /// </summary>
    [Fact]
    public void The_workflow_still_builds_its_agents_through_the_abstraction()
    {
        var agentTypes = AgentTypes().ToList();
        Assert.NotEmpty(agentTypes);

        var buildsFromFactory = typeof(DebateWorkflow)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Any(m => m.GetParameters().Any(p => p.ParameterType == typeof(IChatClientFactory)));

        Assert.True(buildsFromFactory,
            $"{nameof(DebateWorkflow)} must build agents from {nameof(IChatClientFactory)}.");
    }

    /// <summary>
    /// Every agent talks to <see cref="IChatClient"/> and nothing narrower, which is what makes
    /// a provider substitutable at all.
    /// </summary>
    [Fact]
    public void The_factory_hands_back_the_neutral_interface()
    {
        var create = typeof(IChatClientFactory).GetMethod(nameof(IChatClientFactory.Create))!;
        Assert.Equal(typeof(IChatClient), create.ReturnType);
    }

    /// <summary>
    /// Proves the guard has teeth. A test that can only ever pass is not a guard, and this one
    /// is easy to write in a way that silently inspects nothing.
    /// </summary>
    [Fact]
    public void The_guard_detects_a_violation()
    {
        Assert.Contains(Surface(typeof(DeliberateViolation)), IsProviderSpecific);
    }

    /// <summary>A stand-in for the mistake this test exists to catch.</summary>
    private sealed class DeliberateViolation
    {
        public ModelProvider Provider { get; init; }
    }

    private static IEnumerable<Type> AgentTypes() =>
        typeof(DebateWorkflow).Assembly
            .GetTypes()
            .Where(t => t.Namespace is { } ns && AgentNamespaces.Contains(ns));

    private static bool IsProviderSpecific(Type type)
    {
        if (ProviderSpecificTypes.Contains(type))
            return true;

        var root = type.Namespace?.Split('.').FirstOrDefault();
        return root is not null && VendorNamespaceRoots.Contains(root);
    }

    /// <summary>
    /// Every type named anywhere in another type's declaration or method bodies' locals.
    /// </summary>
    private static IEnumerable<Type> Surface(Type type)
    {
        const BindingFlags All = BindingFlags.Public | BindingFlags.NonPublic
            | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

        var referenced = new List<Type?> { type.BaseType };
        referenced.AddRange(type.GetInterfaces());
        referenced.AddRange(type.GetFields(All).Select(f => f.FieldType));
        referenced.AddRange(type.GetProperties(All).Select(p => p.PropertyType));

        foreach (var method in type.GetMethods(All).Cast<MethodBase>().Concat(type.GetConstructors(All)))
        {
            referenced.AddRange(method.GetParameters().Select(p => p.ParameterType));

            if (method is MethodInfo info)
                referenced.Add(info.ReturnType);

            // Locals catch a provider read into a variable inside a method body, which no
            // signature would reveal.
            var locals = SafeLocals(method);
            referenced.AddRange(locals);
        }

        return referenced.Where(t => t is not null).SelectMany(t => Expand(t!)).Distinct();
    }

    /// <summary>
    /// Local variable types, or nothing. Abstract, generic and runtime-generated methods have
    /// no readable body, and that must not fail the whole guard.
    /// </summary>
    private static IEnumerable<Type> SafeLocals(MethodBase method)
    {
        try
        {
            return method.GetMethodBody()?.LocalVariables.Select(v => v.LocalType) ?? [];
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or BadImageFormatException)
        {
            return [];
        }
    }

    /// <summary>Unwraps arrays, by-refs and generic arguments so nesting cannot hide a type.</summary>
    private static IEnumerable<Type> Expand(Type type)
    {
        yield return type;

        if (type.HasElementType && type.GetElementType() is { } element)
            foreach (var inner in Expand(element)) yield return inner;

        if (type.IsGenericType)
            foreach (var argument in type.GetGenericArguments())
                foreach (var inner in Expand(argument)) yield return inner;
    }
}
