using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using TUnit.Core.Interfaces;

public class WebAppFactory : WebApplicationFactory<AuthProgram>, IAsyncInitializer {
    public Task InitializeAsync() {
        
        _ = Server;

        return Task.CompletedTask;
    }
    protected override void ConfigureWebHost(IWebHostBuilder builder) {
        builder.ConfigureAppConfiguration((context, config) => {
            // Optional: clear existing configuration sources
            // config.Sources.Clear();

            var dict = new Dictionary<string, string> {
                ["DOTNET_DATABASE_STRING"] = "Host=localhost;Database=accountAuth;Username=cody;Password=123456abc;",
            };

            config.AddInMemoryCollection(dict!);
        });

        //builder.ConfigureServices(services => {
        //    // Optional: override DI here, or replace services for tests
        //});
    }
}