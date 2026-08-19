using System.Net;
using MediatR;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Auth.Commands.Login;

public class LoginCommandHandler(IUnitOfWork unitOfWork, IPasswordHasher passwordHasher, AuthTokenFactory tokenFactory)
    : IRequestHandler<LoginCommand, Response>
{
    public async Task<Response> Handle(LoginCommand request, CancellationToken ct)
    {
        var email = request.Email.Trim().ToLowerInvariant();

        // Global lookup by design - see IUserRepository.GetByEmailAsync.
        var user = await unitOfWork.UserRepository.GetByEmailAsync(email, ct);

        // Identical message and status whichever half is wrong - telling them apart lets
        // an attacker enumerate which emails have an account here at all.
        if (user is null || !passwordHasher.Verify(user.PasswordHash, request.Password))
            return await Response.FailureAsync("invalid email or password", HttpStatusCode.Unauthorized);

        var tokens = await tokenFactory.IssueAsync(user, ct);

        return await Response.SuccessAsync(tokens, "signed in", HttpStatusCode.OK);
    }
}
