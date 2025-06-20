using Microsoft.AspNetCore.Builder;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccountAuthenticator;

public static class IdentityMiddlewareExtension {
    public static IApplicationBuilder UseAccountIdentityMiddleware(this IApplicationBuilder app, Action<IDMiddlewareConfig>? configureOptions = null) {
        var options = new IDMiddlewareConfig();
        configureOptions?.Invoke(options);

        return app.UseMiddleware<IdentityMiddleware>(options);
    }
}
