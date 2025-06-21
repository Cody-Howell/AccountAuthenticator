# AccountAuthenticator

This is the Username/Password equivalent of the [Email Authenticator](https://github.com/Cody-Howell/EmailAuthenticator)
library. Use that library for sending email and no passwords for your auth, and use this one to enable 
username and password. 

Both work in the same way; they are simple/naive authenticators that primarily use Headers (via the optional Middleware) 
to deal with authentication. The Middleware component automatically checks and validates incoming 
headers, returns helpful strings for what the key is doing, and you can enforce time limits on how long keys are active/
re-enable them every so often so the user only has to sign in once. 

## Features

This library is primarily for locally-hosted, small projects. As of right now, I hold an account name (which must be 
unique across all users) and a password hash. In the future, I might enable 
email-password-reset emails to be sent and generate an HTML page to show the user, but my primary solution 
is that the Admin can reset their password to "password", then they can get back in and change their password. 

Of course, I still have many of the features from the Email auth, with key re-enabling, single sign-out, global 
sign-out, and validation checks. It should feel somewhat similar to that library, just using a different mechanism. 

The middleware configuration was recently reconfigured to work in-line with the app, so you now write some lines like this
to configure the middleware:

```csharp
app.UseAccountIdentityMiddleware(options => {
  options.Paths = ["/users", "/user", "/user/signin"];
  options.Whitelist = "/data";
  options.ExpirationDate = new TimeSpan(30, 0, 0, 0);
  options.ReValidationDate = new TimeSpan(5, 0, 0, 0);
});
```

And an easier way of getting authentication information into your endpoints (to see who is making the request): 

```csharp
app.MapGet("/user/guid", (AccountInfo info) => info.Guid);
app.MapGet("/user/role", (AuthService service, AccountInfo info) => service.GetRole(info.AccountName));
```

See also the readme in the NuGet [package description](https://www.nuget.org/packages/AccountAuthenticator). 

## Initial SQL

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