using SentinelAI.Domain.Abstractions.Repositories;

namespace SentinelAI.Domain.Abstractions;

public interface IUnitOfWork
{
    IGenericRepository<TEntity> Repository<TEntity>() where TEntity : class;
 
    IScanJobRepository ScanJobRepository { get; }

    IUserRepository UserRepository { get; }

    IRefreshTokenRepository RefreshTokenRepository { get; }

    Task<int> CompleteAsync();

    /// <summary>
    /// Throws away every pending change without saving it.
    /// </summary>
    /// <remarks>
    /// For the one case that needs it: recording <em>why</em> a stage failed, when the failure was
    /// a rejected save. The change tracker still holds the rows the database refused, so the next
    /// <see cref="CompleteAsync"/> would resend them and fail identically — the failure reason
    /// would never get written and the original exception would escape twice. Discarding first
    /// leaves a clean unit of work for the status update. Not an undo button for business logic.
    /// </remarks>
    void DiscardChanges();
}