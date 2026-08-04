using System.Net;
using MediatR;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Auth.Commands.Register;

public class RegisterCommandHandler(
    IUnitOfWork unitOfWork,
    IPasswordHasher passwordHasher,
    AuthTokenFactory tokenFactory)
    : IRequestHandler<RegisterCommand, Response>
{
    public async Task<Response> Handle(RegisterCommand request, CancellationToken ct)
    {
        var email = request.Email.Trim().ToLowerInvariant();

        // Global lookup by design - see IUserRepository.GetByEmailAsync.
        if (await unitOfWork.UserRepository.GetByEmailAsync(email, ct) is not null)
            return await Response.FailureAsync("an account with this email already exists", HttpStatusCode.Conflict);

        var now = DateTime.UtcNow;

        var tenant = new Tenant
        {
            Id = Guid.CreateVersion7(),
            Name = request.TenantName.Trim(),
            PlanTier = "free",
            CreatedAt = now,
        };

        var user = new User
        {
            Id = Guid.CreateVersion7(),
            TenantId = tenant.Id,
            Email = email,
            PasswordHash = passwordHasher.Hash(request.Password),
            // First user of a brand-new tenant owns it - there is no one else yet to have
            // granted them anything less.
            Role = Roles.Admin,
            IsEmailVerified = false,
            CreatedAt = now,
        };

        await unitOfWork.Repository<Tenant>().AddAsync(tenant);
        await unitOfWork.Repository<User>().AddAsync(user);
        await unitOfWork.CompleteAsync();

        var tokens = await tokenFactory.IssueAsync(user, ct);

        return await Response.SuccessAsync(tokens, "account created", HttpStatusCode.Created);
    }
}
