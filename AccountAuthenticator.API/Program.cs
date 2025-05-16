using AccountAuthenticator;
using System.Data;
using Npgsql;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

var connString = builder.Configuration["DOTNET_DATABASE_STRING"] ?? throw new InvalidOperationException("Connection string for database not found.");
Console.WriteLine("Connection String: " + connString);
builder.Services.AddSingleton<IDbConnection>(provider => {
    return new NpgsqlConnection(connString);
});
builder.Services.AddSingleton<AuthService>();
builder.Services.AddSingleton<IIDMiddlewareConfig, IDMiddlewareConfig>();

var app = builder.Build();

app.UseMiddleware<IdentityMiddleware>();
app.UseRouting();

app.MapGet("/users", (AuthService service) => service.GetAllUsers());
app.MapPost("/user", (AuthService service, string accountName) => {
    try {
        service.AddUser(accountName);
        return Results.Created();
    } catch (Exception e) {
        return Results.BadRequest(e.Message);
    }
});

app.MapPost("/user/signin", (AuthService service, SignIn obj) => {
    if (service.IsValidUserPass(obj.user, obj.pass)) {
        return Results.Ok(service.NewSignIn(obj.user));
    } else {
        return Results.BadRequest("Invalid Account/Password combo.");
    }
});

app.MapPatch("/user", (AuthService service, SignIn obj) => {
    service.UpdatePassword(obj.user, obj.pass);
    return Results.Ok();
});

app.MapGet("/user/valid", () => Results.Ok());

app.MapDelete("/user/signout", (AuthService service, HttpContext content) => {
    string account = content.Request.Headers["Account-Auth-Account"]!;
    string key = content.Request.Headers["Account-Auth-ApiKey"]!;
    service.KeySignOut(account, key);

    return Results.Accepted();
});

app.MapDelete("/user/signout/global", (AuthService service, HttpContext content) => {
    string account = content.Request.Headers["Account-Auth-Account"]!;
    service.GlobalSignOut(account);

    return Results.Accepted();
});

app.Run();

public class IDMiddlewareConfig : IIDMiddlewareConfig {
    public List<string> Paths => ["/users", "/user", "/user/signin"];
    public TimeSpan? ExpirationDate => null;
    public TimeSpan? ReValidationDate => null;
}
