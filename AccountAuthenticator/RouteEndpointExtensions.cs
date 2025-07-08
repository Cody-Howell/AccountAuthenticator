using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using System.Net;

namespace AccountAuthenticator;

/// <summary>
/// This class contains all of the Endpoint Filters included in the Account Authenticator 
/// library. These provide some clear options for checking against Role and AccountName, as 
/// well as some arbitrary options for checking AccountInfo. 
/// </summary>
public static class RouteEndpointExtensions {
    #region No status code
    /// <summary>
    /// Checks if the requester role is equal to the role provided.
    /// Returns an Unauthorized status code.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsEqualTo(
        this RouteHandlerBuilder builder,
        int role) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole != role) {
                return Results.Unauthorized();
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role is greater than the role provided. 
    /// Returns an Unauthorized status code.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsGreaterThan(
        this RouteHandlerBuilder builder,
        int role) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole <= role) {
                return Results.Unauthorized();
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role is less than the role provided. 
    /// Returns an Unauthorized status code.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsLessThan(
        this RouteHandlerBuilder builder,
        int role) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole >= role) {
                return Results.Unauthorized();
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role is greater than or equal to the role provided. 
    /// Returns an Unauthorized status code.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsGreaterThanOrEqualTo(
        this RouteHandlerBuilder builder,
        int role) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole < role) {
                return Results.Unauthorized();
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role is less than or equal to the role provided. 
    /// Returns an Unauthorized status code.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsLessThanOrEqualTo(
        this RouteHandlerBuilder builder,
        int role) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole > role) {
                return Results.Unauthorized();
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role matches the passed in lambda. It will only allow access 
    /// to the endpoint if the lambda returns <c>TRUE</c>.
    /// Returns an Unauthorized status code.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIs(
        this RouteHandlerBuilder builder,
        Func<int, bool> func) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (!func(userRole)) {
                return Results.Unauthorized();
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester account is equal to the provided string.
    /// Returns an Unauthorized status code.
    /// </summary>
    public static RouteHandlerBuilder RequireAccountNameIsEqualTo(
        this RouteHandlerBuilder builder,
        string accountName) {
        return builder.AddEndpointFilter(async (context, next) => {
            string user = (string)context.HttpContext.Items["Account"]!;
            if (user != accountName) {
                return Results.Unauthorized();
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester account matches the passed in lambda. It will only allow access 
    /// to the endpoint if the lambda returns <c>TRUE</c>.
    /// Returns an Unauthorized status code.
    /// </summary>
    public static RouteHandlerBuilder RequireAccountNameIs(
        this RouteHandlerBuilder builder,
        Func<string, bool> func) {
        return builder.AddEndpointFilter(async (context, next) => {
            string userRole = (string)context.HttpContext.Items["Account"]!;
            if (!func(userRole)) {
                return Results.Unauthorized();
            } else {
                return await next(context);
            }
        });
    }
    #endregion

    #region StatusCode Enum
    /// <summary>
    /// Checks if the requester role is equal to the role provided.
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsEqualTo(
        this RouteHandlerBuilder builder,
        int role,
        HttpStatusCode statusCode = HttpStatusCode.Unauthorized) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole != role) {
                return Results.StatusCode((int)statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role is greater than the role provided. 
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsGreaterThan(
        this RouteHandlerBuilder builder,
        int role,
        HttpStatusCode statusCode = HttpStatusCode.Unauthorized) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole <= role) {
                return Results.StatusCode((int)statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role is less than the role provided. 
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsLessThan(
        this RouteHandlerBuilder builder,
        int role,
        HttpStatusCode statusCode = HttpStatusCode.Unauthorized) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole >= role) {
                return Results.StatusCode((int)statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role is greater than or equal to the role provided. 
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsGreaterThanOrEqualTo(
        this RouteHandlerBuilder builder,
        int role,
        HttpStatusCode statusCode = HttpStatusCode.Unauthorized) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole < role) {
                return Results.StatusCode((int)statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role is less than or equal to the role provided. 
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsLessThanOrEqualTo(
        this RouteHandlerBuilder builder,
        int role,
        HttpStatusCode statusCode = HttpStatusCode.Unauthorized) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole > role) {
                return Results.StatusCode((int)statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role matches the passed in lambda. It will only allow access 
    /// to the endpoint if the lambda returns <c>TRUE</c>.
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIs(
        this RouteHandlerBuilder builder,
        Func<int, bool> func,
        HttpStatusCode statusCode = HttpStatusCode.Unauthorized) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (!func(userRole)) {
                return Results.StatusCode((int)statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester account is equal to the provided string.
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireAccountNameIsEqualTo(
        this RouteHandlerBuilder builder,
        string accountName,
        HttpStatusCode statusCode = HttpStatusCode.Unauthorized) {
        return builder.AddEndpointFilter(async (context, next) => {
            string user = (string)context.HttpContext.Items["Account"]!;
            if (user != accountName) {
                return Results.StatusCode((int)statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester account matches the passed in lambda. It will only allow access 
    /// to the endpoint if the lambda returns <c>TRUE</c>.
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireAccountNameIs(
        this RouteHandlerBuilder builder,
        Func<string, bool> func,
        HttpStatusCode statusCode = HttpStatusCode.Unauthorized) {
        return builder.AddEndpointFilter(async (context, next) => {
            string userRole = (string)context.HttpContext.Items["Account"]!;
            if (!func(userRole)) {
                return Results.StatusCode((int)statusCode);
            } else {
                return await next(context);
            }
        });
    }
    #endregion

    #region Int status code
    /// <summary>
    /// Checks if the requester role is equal to the role provided.
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsEqualTo(
        this RouteHandlerBuilder builder,
        int role,
        int statusCode = 401) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole != role) {
                return Results.StatusCode(statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role is greater than the role provided. 
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsGreaterThan(
        this RouteHandlerBuilder builder,
        int role,
        int statusCode = 401) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole <= role) {
                return Results.StatusCode(statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role is less than the role provided. 
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsLessThan(
        this RouteHandlerBuilder builder,
        int role,
        int statusCode = 401) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole >= role) {
                return Results.StatusCode(statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role is greater than or equal to the role provided. 
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsGreaterThanOrEqualTo(
        this RouteHandlerBuilder builder,
        int role,
        int statusCode = 401) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole < role) {
                return Results.StatusCode(statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role is less than or equal to the role provided. 
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIsLessThanOrEqualTo(
        this RouteHandlerBuilder builder,
        int role,
        int statusCode = 401) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (userRole > role) {
                return Results.StatusCode(statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester role matches the passed in lambda. It will only allow access 
    /// to the endpoint if the lambda returns <c>TRUE</c>.
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireRoleIs(
        this RouteHandlerBuilder builder,
        Func<int, bool> func,
        int statusCode = 401) {
        return builder.AddEndpointFilter(async (context, next) => {
            int userRole = (int)context.HttpContext.Items["Role"]!;
            if (!func(userRole)) {
                return Results.StatusCode(statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester account is equal to the provided string.
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireAccountNameIsEqualTo(
        this RouteHandlerBuilder builder,
        string accountName,
        int statusCode = 401) {
        return builder.AddEndpointFilter(async (context, next) => {
            string user = (string)context.HttpContext.Items["Account"]!;
            if (user != accountName) {
                return Results.StatusCode(statusCode);
            } else {
                return await next(context);
            }
        });
    }

    /// <summary>
    /// Checks if the requester account matches the passed in lambda. It will only allow access 
    /// to the endpoint if the lambda returns <c>TRUE</c>.
    /// Returns a default Unauthorized status code, overridable in the parameter.
    /// </summary>
    public static RouteHandlerBuilder RequireAccountNameIs(
        this RouteHandlerBuilder builder,
        Func<string, bool> func,
        int statusCode = 401) {
        return builder.AddEndpointFilter(async (context, next) => {
            string userRole = (string)context.HttpContext.Items["Account"]!;
            if (!func(userRole)) {
                return Results.StatusCode(statusCode);
            } else {
                return await next(context);
            }
        });
    }
    #endregion
}
