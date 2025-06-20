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

var app = builder.Build();

app.UseAccountIdentityMiddleware(options => {
    options.Paths = ["/users", "/user", "/user/signin"];
});
app.UseRouting();

app.MapGet("/users", (AuthService service) => service.GetAllUsers());
app.MapGet("/user", (AuthService service, string account) => service.GetUser(account));
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
app.MapPatch("/user/role", (AuthService service, AccountInfo info, int newRole) => {
    service.UpdateRole(info.AccountName, newRole);
    return Results.Ok();
});

app.MapGet("/user/valid", () => Results.Ok());
app.MapGet("/user/guid", (AccountInfo info) => info.Guid);
app.MapGet("/user/role", (AuthService service, AccountInfo info) => service.GetRole(info.AccountName));

app.MapDelete("/user/signout", (AuthService service, AccountInfo info) => {
    service.KeySignOut(info.AccountName, info.ApiKey);

    return Results.Accepted();
});
app.MapDelete("/user/signout/global", (AuthService service, AccountInfo info) => {
    service.GlobalSignOut(info.AccountName);

    return Results.Accepted();
});

app.Run();
