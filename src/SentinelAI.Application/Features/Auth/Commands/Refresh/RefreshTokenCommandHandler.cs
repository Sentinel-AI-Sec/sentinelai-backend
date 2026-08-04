using System.Net;
using MediatR;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Auth.Commands.Refresh;

public class RefreshTokenCommandHandler(IUnitOfWork unitOfWork, IJwtTokenIssuer tokenIssuer, AuthTokenFactory tokenFactory)
    : IRequestHandler<RefreshTokenCommand, Response>
{
    public async Task<Response> Handle(RefreshTokenCommand request, CancellationToken ct)
    {
        var hash = tokenIssuer.HashRefreshToken(request.RefreshToken);
        var stored = await unitOfWork.RefreshTokenRepository.GetByTokenHashAsync(hash, ct);

        if (stored is null || stored.User is null || stored.RevokedAt is not null || stored.ExpiresAt <= DateTime.UtcNow)
            return await Response.FailureAsync("invalid or expired refresh token", HttpStatusCode.Unauthorized);

        // Rotate rather than reuse: this refresh token is single-use. A copy sitting in
        // some attacker's hands stops working the instant its legitimate owner refreshes
        // first, rather than staying valid until it naturally expires.
        stored.RevokedAt = DateTime.UtcNow;
        await unitOfWork.CompleteAsync();

        var tokens = await tokenFactory.IssueAsync(stored.User, ct);

        return await Response.SuccessAsync(tokens, "token refreshed", HttpStatusCode.OK);
    }
}
