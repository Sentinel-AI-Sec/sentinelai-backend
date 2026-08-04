using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Auth.Commands.Register;

/// <summary>Self-service: always creates a brand-new tenant with the registering user as
/// its first admin. Joining an existing tenant is a separate, invite-only flow.</summary>
public sealed record RegisterCommand(string Email, string Password, string TenantName) : IRequest<Response>;
