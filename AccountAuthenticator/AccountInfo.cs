using Microsoft.AspNetCore.Http;
using System.Data;
using System.Reflection;

namespace AccountAuthenticator;

/// <summary>
/// Encapsulates Account Name, ApiKey, and Guid of the incoming request. 
/// Smoother encapsulation for endpoints, just use this as a parameter and it 
/// will collect the information for you, or appropriately throw errors. 
/// </summary>
public class AccountInfo {
    /// <summary>
    /// Account Name of the incoming request
    /// </summary>
    public string AccountName { get; }
    /// <summary>
    /// Api Key of the incoming request
    /// </summary>
    public string ApiKey { get; }
    /// <summary>
    /// Guid of the incoming request
    /// </summary>
    public Guid Guid { get; }

    private AccountInfo(string accountName, string apiKey, Guid guid) {
        AccountName = accountName;
        ApiKey = apiKey;
        Guid = guid;
    }

    /// <summary>
    /// Is this even visible? I don't think so. 
    /// </summary>
    public static ValueTask<AccountInfo> BindAsync(HttpContext context, ParameterInfo parameter) {
        if (!context.Request.Headers.TryGetValue("Account-Auth-Account", out var headerValue)) {
            throw new UnauthorizedAccessException("Missing account header.");
        }
        if (!context.Request.Headers.TryGetValue("Account-Auth-ApiKey", out var apiKey)) {
            throw new UnauthorizedAccessException("Missing account header.");
        }
        Guid guid = (Guid)context.Items["Guid"];

        return ValueTask.FromResult(new AccountInfo(headerValue!, apiKey!, guid));
    }
}
