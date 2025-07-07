namespace AccountAuthenticator;

using Microsoft.AspNetCore.Http;

/// <summary>
/// Identity Middleware relies on the <c>IIDMiddlewareConfig</c> to be injected through DI, as well as the AuthService. 
/// For any error, it will throw a <c>401</c> HTTP code with a string (of which 3 are user-friendly). Make sure 
/// the headers always contain a little bit of information, as the 4th is developer-intended. 
/// <br/> <br/>
/// This takes every path not in Paths of the config and checks for email and API Key headers. If they are 
/// null or empty, the response will give you the exact syntax. <br/>
/// Afterwards, they will validate that you have a valid API key, and return a short, helpful message if not so. <br/>
/// Finally, if the ExpirationDate is not null, it will calculate the time between. If it's over the expiration date, 
/// it will remove that key. If it's under but over the re-auth time (also assuming config), it will 
/// reset the expiration date. Then it will let the response pass. 
/// </summary>
public class IdentityMiddleware(RequestDelegate next, AuthService service, IDMiddlewareConfig config) {
    /// <summary>
    /// 
    /// </summary>
    public async Task InvokeAsync(HttpContext context) {
        bool startsWith = false;
        if (config.Whitelist is not null) {
            startsWith = !context.Request.Path.ToString().StartsWith(config.Whitelist);
        }


        if (config.Paths.Contains(context.Request.Path) || startsWith) {
            await next(context);
        } else {
            // Validate user here
            string? account = context.Request.Headers["Account-Auth-Account"];
            string? key = context.Request.Headers["Account-Auth-ApiKey"];
            if (string.IsNullOrEmpty(account) || string.IsNullOrEmpty(key)) {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized: Missing header(s).\nRequires an \"Account-Auth-Account\" and \"Account-Auth-ApiKey\" header.");
                return;
            }

            try {
                Account acc = service.GetUser(account);
                context.Items["Guid"] = acc.Id;
                context.Items["Role"] = acc.Role;
            } 
            catch {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Account does not exist.");
                return;
            }


            DateTime? output;
            try {
                output = service.IsValidApiKey(account, key);
            } catch {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("API key does not exist.");
                return;
            }

            if (config.ExpirationDate is null) {
                await next(context);
                return;
            }


            TimeSpan? timeBetween = DateTime.Now.ToUniversalTime() - output;
            if (timeBetween < config.ExpirationDate) {
                if (config.ReValidationDate is not null &&
                    timeBetween > config.ReValidationDate) {
                    service.ReValidate(account, key);
                }

                await next(context);
            } else {
                // Explicit cast removes the null check that's completed above
                service.ExpiredKeySignOut((TimeSpan)config.ExpirationDate);
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Time has run out. Please sign in again.");
            }
        }
    }
}

