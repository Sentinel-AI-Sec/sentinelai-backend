using SentinelAI.Domain.Abstractions.Repositories;

namespace SentinelAI.Domain.Abstractions;

public interface IUnitOfWork
{
    IGenericRepository<TEntity> Repository<TEntity>() where TEntity : class;
 
    IScanJobRepository ScanJobRepository { get; }

    IUserRepository UserRepository { get; }

    IRefreshTokenRepository RefreshTokenRepository { get; }

    Task<int> CompleteAsync();
}