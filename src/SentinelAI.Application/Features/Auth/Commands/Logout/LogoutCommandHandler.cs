using MediatR;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Auth.Commands.Logout;

public class LogoutCommandHandler(IUnitOfWork unitOfWork, IJwtTokenIssuer tokenIssuer)
    : IRequestHandler<LogoutCommand, Response>
{
    public async Task<Response> Handle(LogoutCommand request, CancellationToken ct)
    {
        var hash = tokenIssuer.HashRefreshToken(request.RefreshToken);
        var stored = await unitOfWork.RefreshTokenRepository.GetByTokenHashAsync(hash, ct);

        // Logging out an already-invalid or unknown token isn't an error - the caller's
        // goal (this token no longer works) is already true either way.
        if (stored is not null && stored.RevokedAt is null)
        {
            stored.RevokedAt = DateTime.UtcNow;
            await unitOfWork.CompleteAsync();
        }

        return await Response.SuccessAsync("signed out");
    }
}
