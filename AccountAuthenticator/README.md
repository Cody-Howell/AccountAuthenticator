# AccountAuthenticator

Read the docs [at this link](https://wiki.codyhowell.dev/accountauth).

This authenticator provides an AuthService, an IdentityMiddleware, and some helpful parameters and extensions 
for minimalAPIs. This is a similarly naive authenticator that handles an account/password combo, but works in essentially the 
same way as the EmailAuthenticator. 

Recommended API layout in `Program.cs`: 

```csharp
builder.Services.AddSingleton<AuthService>();

var app = builder.Build();

app.UseAccountIdentityMiddleware(options => {
    // Apply Path, Whitelist, Timespan, or Logging objects here
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
- Endpoint filters that take place of IdentityMiddleware for projects that only need to secure a few endpoints
    - This includes extracting that logic into an external class, which could be read by you as well
- A default map for signin, signout, and change password (this may be expanded later)
    - Ex. mapping some default (optional) GET and POST requests to keep them out of your way
    - This would include both a C# and JS client package for immediate usage in Blazor (C#) and any JS app
- Change AuthService implementation to: 
    - Enable/disable caching of roles and GUID
    - Write code to enable/disable caching of API keys
    - Instead of adjusting cache directly, should just invalidate it
    - This would include a rewrite of the singleton registration to match the `UseAccountIdentityMiddleware` function
    - (with long-term-planning 1 below): set a TimeSpan which will clear the cache asynchronously

For items in long-term storage: 

- LONG-TERM PLANNING
    1. Dictionary caching limit, where you can specify a size to keep the dictionary to and it will manage the number of items. This would take a significant amount of memory and computation when something needed to be deleted, but for larger projects, it would be better than allowing the dictionaries to go to infinity. 
        - This would be specified per-cache (mostly), so I would have one for Roles and GUID (since they are always called at the same time for the same account), and one for each Key. 
    1. Account Name Switching. Currently, there are no functions to allow you to change the account name. One could be written that checks if the account name is already in use, and if not, allows you to change a user given the GUID. This should also invalidate all cache related to that account name.

## Changelog

3.0.1 - Beta (11/19/25)

- Changed into a concurrent dictionary for the lookups

3.0 - Beta (9/18/25)

Version 3 came *way* faster than I wanted. I'll be sitting in beta for a few months so I reduce the chance 
of me spamming major versions. I intended to keep it low..

I need to change major versions because I need to update the SQL for initialization. I knew that I should for some time, but 
our project has determined that we need salted hashes for the password values. I already have the tools needed to implement 
it, but I just.. didn't, for the major version I implemented a week ago. 

As mentioned, I'll be in beta (and likely releasing bug-fix versions whenever we need an update), then once we've been using
it for long enough, I imagine I can release a more complete version 3.0. 

The goals I intend to complete are listed above in the **Upcoming Features** heading. They will be moved out of there into the bugfix patches whenever I complete a new version. Below are the ones I've done for this version. 

- Salted hashes (Invalidates all prior hashes in a table)
- Removed some features of String Helper
- Added minor logging to the three async Search functions 

2.0.1 (9/17/25)

Added a GetCurrentSessionCount method to get the current number of keys (not entirely validated) in the table. 

Also of note, the non-Async methods have not been as thoroughly tested as the Async methods. 

2.0 (9/10/25)

A few additional features have been added. The middleware configuration now has a Logging 
system, turned off by default. There is an internal (but accessible) class called DbConnector which 
helps encapsulate Dapper queries correctly. 

The AuthService now has Async and sync methods by default. I believe logging will be added to that 
at a future time as well, maybe with it's own configuration system. 

Please see the docs (and scroll to the bottom) for new version 2.0 functions and more specificity. 

This is still under test and subject to be bugfixed within the next few weeks of release. We're using 
it in a current project and hopefully will run into all the problems ourselves. 

2.0 - Alpha (8/22/25)

Version 2 came much faster than I wanted. 

I started to actually use this in a project. I was building an SPA and I generated a few items that 
made concurrent calls to the API. The AuthService broke because the connection was trying to be 
shared, and after many discussions with ChatGPT (and internal crying), I built this Alpha version 
to test. All AuthService method names and return types have been adjusted to be async. 

It includes a `DbConnector` class to inject and get new async managed connections. We will see if 
this fixes everything; assuming so, for the final release of 2.0, I will try and figure out non-async 
methods. 

This no longer requires an `IDbConnection` DI injection, but it looks like all other notes above 
maintain. I'll adjust those with version-specific updates once 2.0 comes out in full release. 

1.2 (7/7/25)

- AuthService new Accounts now have a place to set a default Role number. 
- Generated a number of Endpoint filters to help with clean authorization. A few code examples will be provided below (see wiki for more). 
- IdentityMiddleware now passes the Account through `HttpContext.Items`.
- .csproj has removed the "Microsoft.AspNetCore.Http" reference in favor of the "Microsoft.AspNetCore.App" framework

```csharp
app.MapGet(...).RequireRoleIsEqualTo(3);
app.MapGet(...).RequireRoleIsGreaterThan(2, HttpStatusCode.Forbidden);
app.MapGet(...).RequireRoleIsLessThan(4, 403);
app.MapGet(...).RequireRoleIs(i => i > 4); // Obviously this function can be done in other ways, but this shows how it can work.
```

These could also be used as simpler methods to return custom error codes depending on the role of the user. 

1.1 (7/6/25)

- AccountInfo now includes Role property, making role checking much cleaner. Should've done this from the start.

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
app.MapGet("/user/role", (AccountInfo info) => info.Role);
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