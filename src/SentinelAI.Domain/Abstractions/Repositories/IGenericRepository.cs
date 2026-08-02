using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore.Storage;

namespace SentinelAI.Domain.Abstractions.Repositories;

public interface IGenericRepository<T> where T : class
{
    /// <summary>Looks up by primary key as configured in EF, whatever its shape.</summary>
    Task<T?> GetByIdAsync(params object[] keyValues);
 
    Task<IEnumerable<T>> GetAllAsync();
    Task<IEnumerable<T>> GetWhereAsync(Expression<Func<T, bool>> predicate);
 
    /// <summary>Deferred, so callers can keep chaining Select/OrderBy before execution.</summary>
    IQueryable<T> Where(Expression<Func<T, bool>> predicate);
    IQueryable<TResult> Select<TResult>(Expression<Func<T, TResult>> selector);
 
    IQueryable<T> GetTableAsTracked();
    IQueryable<T> GetTableAsNotTracked();
 
    Task AddAsync(T entity);
    Task AddRangeAsync(ICollection<T> entities);
    Task UpdateAsync(T entity);
    Task UpdateRangeAsync(ICollection<T> entities);
    Task DeleteAsync(T entity);
    Task DeleteRangeAsync(ICollection<T> entities);
 
    Task<bool> AnyAsync(Expression<Func<T, bool>> predicate);
 
    Task SaveChangesAsync();
 
    IDbContextTransaction BeginTransaction();
    void Commit();
    void RollBack();
}