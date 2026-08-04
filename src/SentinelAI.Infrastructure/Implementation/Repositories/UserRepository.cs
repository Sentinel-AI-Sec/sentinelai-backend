using Microsoft.EntityFrameworkCore;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

public class UserRepository(SentinelDbContext context) : IUserRepository
{
    public async Task<User?> GetByEmailAsync(string email, CancellationToken ct = default)
        => await context.Users
            .IgnoreQueryFilters() // see IUserRepository.GetByEmailAsync
            .AsNoTracking()
            .FirstOrDefaultAsync(u => u.Email == email, ct);
}
