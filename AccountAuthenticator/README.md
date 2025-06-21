# AccountAuthenticator

This authenticator provides a few interfaces, an AuthService, and an IdentityMiddleware. This is a 
similarly naive authenticator that handles an account/password combo, but works in essentially the 
same way as the EmailAuthenticator. 

Recommended API layout in `Program.cs`: 

```csharp
builder.Services.AddSingleton<AuthService>();

var app = builder.Build();

app.UseAccountIdentityMiddleware(options => {
    // Apply Path, Whitelist, or Date timings here
});
```

Important headers: 
```
Account-Auth-Account: {{Username}}
Account-Auth-ApiKey: {{Key}}
```

You can check the XML comments for my extension method and the AccountInfo parameter, and you can use
the source repository API as a sample usage. 

## SQL

This SQL is a requirement for the Service to work properly. Since I'm using Dapper, you need 
a Postgres database with the following SQL tables: 

```sql
CREATE TABLE "HowlDev.User" (
  id UUID PRIMARY KEY,
  accountName varchar(200) UNIQUE NOT NULL, 
  passHash varchar(200) NOT NULL, 
  role int NOT NULL
);

CREATE TABLE "HowlDev.Key" (
  id int PRIMARY KEY GENERATED ALWAYS AS IDENTITY NOT NULL,
  accountId varchar(200) references "HowlDev.User" (accountName) NOT NULL, 
  apiKey varchar(20) NOT NULL,
  validatedOn timestamp NOT NULL
);
```

This can be added to as much as you like to encode more information (for example in the User table), 
but this is what's required to make my auth work. 

## Upcoming Features

A few more features are coming before I consider the library done. 
- Integration tests with the Docker Compose to run full auth flows
	- Test throwing errors and what you should expect as a return value 
- Move headers to standard `Authentication` header (for both libraries)
    - AS OF 0.9 - My library works in a fundamentally different way, will not be migrating to this for v1.x

## Changelog

1.0 (!) (6/20/25)

- Attempted writing some tests, will not worry about that for the .0 release. Check back in to the repo to check test status.

0.9.0 (6/19/25)

- BREAKING CHANGES
	- Changed DB to include UUID's instead of sequential ints 
	- Otherwise simplified the database schema to only include necessities (and roles, I think roles are important)
	- Entirely removed MiddlewareConfig interface, moved it to a new extension method for the app (see below)
- Included a new class to more easily get auth information into your endpoints. Use the AccountInfo parameter!
- Added a few AuthService methods to retrieve Role and Guid information
- Added more methods to update values within the database

How to use the new middleware setup: 

```csharp
app.UseAccountIdentityMiddleware(options => {
  options.Paths = ["/users", "/user", "/user/signin"];
  options.Whitelist = "/data";
  options.ExpirationDate = new TimeSpan(30, 0, 0, 0);
  options.ReValidationDate = new TimeSpan(5, 0, 0, 0);
});
```

Any option not configured has defaults, so you can remove the lambda entirely (though for various 
reasons, I don't recommend doing that), or you can just configure the options you want. 

Sample of the AccountInfo parameter for minimal endpoints: 

```csharp
app.MapGet("/user/guid", (AccountInfo info) => info.Guid);
app.MapGet("/user/role", (AuthService service, AccountInfo info) => service.GetRole(info.AccountName));
```

0.8.4 (5/19/25)

- Removed last bugfix. 
- Updated information on this Readme
- BREAKING CHANGE: IIDMiddlewareConfig now has an additional `Whitelist` property, *actually* enabling SPAs.

0.8.2 (5/19/25)

- IdentityMiddleware does not enforce path restrictions to anything in /assets, allowing for SPAs.

0.8.1 (5/16/25)

- GetUser now takes and checks an AccountName instead of an Email.

0.8 (5/15/25)

- Init