using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Auth.Commands.Login;

public sealed record LoginCommand(string Email, string Password) : IRequest<Response>;
