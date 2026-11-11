using Microsoft.AspNetCore.Diagnostics;
using Npgsql;

namespace MerkleAudit.Server.Infrastructure;

/// <summary>
/// Database contention and outages become a retryable 503 with Retry-After. An append that fails this way was rolled
/// back as a whole (no sequence number was consumed), so the client can simply send it again.
/// </summary>
internal sealed class DatabaseExceptionHandler(IProblemDetailsService problems) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        var retryable = exception switch
        {
            PostgresException { SqlState: PostgresErrorCodes.LockNotAvailable or PostgresErrorCodes.SerializationFailure or PostgresErrorCodes.DeadlockDetected } => true,
            NpgsqlException { IsTransient: true } => true,
            TimeoutException => true,
            _ => false,
        };

        if (!retryable)
        {
            return false;
        }

        httpContext.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        httpContext.Response.Headers.RetryAfter = "1";
        return await problems.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails =
            {
                Status = StatusCodes.Status503ServiceUnavailable,
                Title = "Temporarily unavailable, retry.",
            },
            Exception = exception,
        });
    }
}
