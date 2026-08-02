using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
using SentinelAI.Domain.Abstractions.Repositories;
using SentinelAI.Infrastructure.Data;

namespace SentinelAI.Infrastructure.Implementation.Repositories;

public class GenericRepository<T>(SentinelDbContext context) : IGenericRepository<T> where T : class
{
    public async Task<T?> GetByIdAsync(params object[] keyValues) => await context.Set<T>().FindAsync(keyValues);
 
    public async Task<IEnumerable<T>> GetAllAsync() => await context.Set<T>().ToListAsync();
 
    public async Task<IEnumerable<T>> GetWhereAsync(Expression<Func<T, bool>> predicate)
        => await context.Set<T>().Where(predicate).ToListAsync();
 
    public IQueryable<T> Where(Expression<Func<T, bool>> predicate)
        => context.Set<T>().Where(predicate);
 
    public IQueryable<TResult> Select<TResult>(Expression<Func<T, TResult>> selector)
        => context.Set<T>().Select(selector);
 
    public IQueryable<T> GetTableAsTracked() => context.Set<T>().AsQueryable();
 
    public IQueryable<T> GetTableAsNotTracked() => context.Set<T>().AsNoTracking().AsQueryable();
 
    public async Task AddAsync(T entity) => await context.Set<T>().AddAsync(entity);
 
    public async Task AddRangeAsync(ICollection<T> entities) => await context.Set<T>().AddRangeAsync(entities);
 
    public Task UpdateAsync(T entity)
    {
        context.Set<T>().Update(entity);
        return Task.CompletedTask;
    }
 
    public Task UpdateRangeAsync(ICollection<T> entities)
    {
        context.Set<T>().UpdateRange(entities);
        return Task.CompletedTask;
    }
 
    public Task DeleteAsync(T entity)
    {
        context.Set<T>().Remove(entity);
        return Task.CompletedTask;
    }
 
    public Task DeleteRangeAsync(ICollection<T> entities)
    {
        context.Set<T>().RemoveRange(entities);
        return Task.CompletedTask;
    }
 
    public async Task<bool> AnyAsync(Expression<Func<T, bool>> predicate)
        => await context.Set<T>().AnyAsync(predicate);
 
    public async Task SaveChangesAsync() => await context.SaveChangesAsync();
 
    public IDbContextTransaction BeginTransaction() => context.Database.BeginTransaction();
 
    public void Commit() => context.Database.CommitTransaction();
 
    public void RollBack() => context.Database.RollbackTransaction();
}