using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore.Storage;
using SentinelAI.Domain.Abstractions;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Domain.Models;

namespace SentinelAI.Integration.Tests.Scan;

/// <summary>
/// Hand-rolled fakes for <see cref="SubmitScanCommandHandler"/>'s dependencies — this
/// project has no mocking library, and the handler's ports are narrow enough that faking
/// them directly is clearer than adding one for a single command.
/// </summary>
internal sealed class FakeCallerContext : ICallerContext
{
    public bool IsAuthenticated { get; init; } = true;
    public Guid? TenantId { get; init; } = Guid.NewGuid();
    public Guid? UserId { get; init; }
    public HashSet<string> Scopes { get; init; } = [AuthScopes.ScanWrite];
    public string? Role { get; init; }

    public bool HasScope(string scope) => Scopes.Contains(scope);
}

internal sealed class FakeCorpusVersionProvider : ICorpusVersionProvider
{
    public string Version { get; init; } = "test-corpus-v1";

    public Task<string> GetCurrentVersionAsync(CancellationToken ct) => Task.FromResult(Version);
}

internal sealed class FakeBundleStore : IBundleStore
{
    public Dictionary<Guid, byte[]> Saved { get; } = [];

    public async Task<string> SaveAsync(Guid scanJobId, Stream bundle, CancellationToken ct)
    {
        using var buffer = new MemoryStream();
        await bundle.CopyToAsync(buffer, ct);
        Saved[scanJobId] = buffer.ToArray();
        return $"fake://{scanJobId}";
    }

    public Task PurgeAsync(Guid scanJobId, CancellationToken ct)
    {
        Saved.Remove(scanJobId);
        return Task.CompletedTask;
    }
}

internal sealed class FakeScanJobRepository : IScanJobRepository
{
    public Project? Project { get; init; }

    public Task<ScanJob?> GetForTenantAsync(Guid scanJobId, Guid tenantId, CancellationToken ct = default)
        => Task.FromResult<ScanJob?>(null);

    public Task<Project?> GetProjectForTenantAsync(Guid projectId, Guid tenantId, CancellationToken ct = default)
        => Task.FromResult(Project is not null && Project.Id == projectId && Project.TenantId == tenantId
            ? Project
            : null);
}

/// <summary>Records what the handler tries to persist. Only <see cref="AddAsync"/> is
/// exercised by <c>SubmitScanCommandHandler</c>; everything else throws if it's ever hit,
/// which would mean the handler started relying on a query path this fake does not model.</summary>
internal sealed class FakeGenericRepository<T> : IGenericRepository<T> where T : class
{
    public List<T> Added { get; } = [];

    public Task AddAsync(T entity)
    {
        Added.Add(entity);
        return Task.CompletedTask;
    }

    public Task<T?> GetByIdAsync(params object[] keyValues) => throw new NotSupportedException();
    public Task<IEnumerable<T>> GetAllAsync() => throw new NotSupportedException();
    public Task<IEnumerable<T>> GetWhereAsync(Expression<Func<T, bool>> predicate) => throw new NotSupportedException();
    public IQueryable<T> Where(Expression<Func<T, bool>> predicate) => throw new NotSupportedException();
    public IQueryable<TResult> Select<TResult>(Expression<Func<T, TResult>> selector) => throw new NotSupportedException();
    public IQueryable<T> GetTableAsTracked() => throw new NotSupportedException();
    public IQueryable<T> GetTableAsNotTracked() => throw new NotSupportedException();
    public Task AddRangeAsync(ICollection<T> entities) => throw new NotSupportedException();
    public Task UpdateAsync(T entity) => throw new NotSupportedException();
    public Task UpdateRangeAsync(ICollection<T> entities) => throw new NotSupportedException();
    public Task DeleteAsync(T entity) => throw new NotSupportedException();
    public Task DeleteRangeAsync(ICollection<T> entities) => throw new NotSupportedException();
    public Task<bool> AnyAsync(Expression<Func<T, bool>> predicate) => throw new NotSupportedException();
    public Task SaveChangesAsync() => throw new NotSupportedException();
    public IDbContextTransaction BeginTransaction() => throw new NotSupportedException();
    public void Commit() => throw new NotSupportedException();
    public void RollBack() => throw new NotSupportedException();
}

internal sealed class FakeUnitOfWork(IScanJobRepository scanJobRepository) : IUnitOfWork
{
    private readonly Dictionary<Type, object> _repositories = [];

    public IScanJobRepository ScanJobRepository { get; } = scanJobRepository;

    // Unused by SubmitScanCommandHandlerTests - throw if that ever changes rather than
    // silently returning null and masking a missing fake.
    public IUserRepository UserRepository => throw new NotSupportedException();
    public IRefreshTokenRepository RefreshTokenRepository => throw new NotSupportedException();

    public int CompleteCallCount { get; private set; }

    public IGenericRepository<TEntity> Repository<TEntity>() where TEntity : class
    {
        if (!_repositories.TryGetValue(typeof(TEntity), out var repo))
        {
            repo = new FakeGenericRepository<TEntity>();
            _repositories[typeof(TEntity)] = repo;
        }

        return (IGenericRepository<TEntity>)repo;
    }

    public FakeGenericRepository<TEntity> FakeRepository<TEntity>() where TEntity : class
        => (FakeGenericRepository<TEntity>)Repository<TEntity>();

    public Task<int> CompleteAsync()
    {
        CompleteCallCount++;
        return Task.FromResult(0);
    }
}
