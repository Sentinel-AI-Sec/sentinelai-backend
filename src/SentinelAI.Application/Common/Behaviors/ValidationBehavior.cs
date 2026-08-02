using System.Net;
using FluentValidation;
using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Common.Behaviors;

/// <summary>
/// Runs every registered <see cref="IValidator{T}"/> for a request before its handler.
/// A failed validator never reaches the handler; without this, a validator class like
/// <c>SubmitScanCommandValidator</c> is dead code that MediatR never calls.
/// </summary>
public sealed class ValidationBehavior<TRequest, TResponse>(IEnumerable<IValidator<TRequest>> validators)
    : IPipelineBehavior<TRequest, TResponse>
    where TRequest : IRequest<TResponse>
    where TResponse : Response, new()
{
    public async Task<TResponse> Handle(
        TRequest request, RequestHandlerDelegate<TResponse> next, CancellationToken cancellationToken)
    {
        if (!validators.Any())
            return await next();

        var failures = (await Task.WhenAll(
                validators.Select(v => v.ValidateAsync(request, cancellationToken))))
            .SelectMany(result => result.Errors)
            .ToList();

        if (failures.Count == 0)
            return await next();

        return new TResponse
        {
            IsSuccess = false,
            StatusCode = HttpStatusCode.BadRequest,
            Message = string.Join(" | ", failures.Select(f => f.ErrorMessage)),
        };
    }
}
