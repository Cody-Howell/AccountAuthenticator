using Microsoft.AspNetCore.Http;
using System.Reflection;

namespace AccountAuthenticator;

/// <summary>
/// Encapsulates Account Name, ApiKey, Role, and Guid of the incoming request. 
/// Enables smoother encapsulation for endpoints, just use this as a parameter and it 
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
    /// <summary>
    /// Role of the incoming user
    /// </summary>
    public int Role { get; }

    private AccountInfo(string accountName, string apiKey, Guid guid, int role) {
        AccountName = accountName;
        ApiKey = apiKey;
        Guid = guid;
        Role = role;
    }

    /// <summary>
    /// Is this even visible? I don't think so. 
    /// </summary>
    public static ValueTask<AccountInfo> BindAsync(HttpContext context, ParameterInfo parameter) {
        if (!context.Request.Headers.TryGetValue("Account-Auth-Account", out var accountName)) {
            throw new Exception("Do not use without IdentityMiddleware; wrong path (missing account)");
        }
        if (!context.Request.Headers.TryGetValue("Account-Auth-ApiKey", out var apiKey)) {
            throw new Exception("Do not use without IdentityMiddleware; wrong path (missing API key)");
        }
        Guid guid = (Guid)context.Items["Guid"]!;
        int role = (int)context.Items["Role"]!;

        return ValueTask.FromResult(new AccountInfo(accountName!, apiKey!, guid, role));
    }
}
