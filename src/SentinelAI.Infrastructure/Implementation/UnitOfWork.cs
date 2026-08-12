using System.Collections;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Infrastructure.Data;
using SentinelAI.Infrastructure.Implementation.Repositories;

namespace SentinelAI.Infrastructure.Implementation;

public class UnitOfWork(
    SentinelDbContext context,
    IScanJobRepository scanJobRepository,
    IUserRepository userRepository,
    IRefreshTokenRepository refreshTokenRepository) : IUnitOfWork
{
    private readonly Hashtable _repositories = new();

    public IScanJobRepository ScanJobRepository { get; } = scanJobRepository;

    public IUserRepository UserRepository { get; } = userRepository;

    public IRefreshTokenRepository RefreshTokenRepository { get; } = refreshTokenRepository;
 
    public IGenericRepository<TEntity> Repository<TEntity>() where TEntity : class
    {
        var key = typeof(TEntity).Name;
 
        if (!_repositories.ContainsKey(key))
            _repositories.Add(key, new GenericRepository<TEntity>(context));
 
        return (IGenericRepository<TEntity>)_repositories[key]!;
    }
 
    public Task<int> CompleteAsync() => context.SaveChangesAsync();

    public void DiscardChanges() => context.ChangeTracker.Clear();
}