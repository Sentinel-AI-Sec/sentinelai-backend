using MediatR;
using SentinelAI.Domain.Premitives;

namespace SentinelAI.Application.Features.Scan.Commands.Submit;

public sealed record SubmitScanCommand(string MetadataJson, Stream Bundle) : IRequest<Response>;