using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccountAuthenticator;

/// <summary>
/// Unused XML comment
/// </summary>
public static class IdentityMiddlewareExtension {
    /// <summary>
    /// Enables the Identity Middleware for AccountAuthenticator. Create a lambda to configure options
    /// previously held in IIDMiddlewareConfig, with an example below.
    /// <code>
    /// app.UseAccountIdentityMiddleware(options => {
    ///   options.Paths = ["/users", "/user", "/user/signin"];
    ///   options.Whitelist = "/data";
    ///   options.ExpirationDate = new TimeSpan(30, 0, 0, 0);
    ///   options.ReValidationDate = new TimeSpan(5, 0, 0, 0);
    /// });
    /// </code>
    /// </summary>
    public static IApplicationBuilder UseAccountIdentityMiddleware(this IApplicationBuilder app, Action<IDMiddlewareConfig>? configureOptions = null) {
    var options = new IDMiddlewareConfig();
    configureOptions?.Invoke(options);

    return app.UseMiddleware<IdentityMiddleware>(options);
}
}
