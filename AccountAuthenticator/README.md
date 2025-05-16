# AccountAuthenticator

This authenticator provides a few interfaces, an AuthService, and an IdentityMiddleware. This is a 
similarly naive authenticator that handles an account/password combo, but works in essentially the 
same way as the EmailAuthenticator. 

Recommended API layout in `Program.cs`: 

```csharp
builder.Services.AddSingleton<AuthService>();
builder.Services.AddSingleton<IIDMiddlewareConfig, IDMiddlewareConfig>();
builder.Services.AddSingleton<IEmailService, EmailService>();

var app = builder.Build();

app.UseMiddleware<IdentityMiddleware>();
```

Important headers: 
```
Email-Auth-Email: {{email}}
Email-Auth-ApiKey: {{key}}
```

## SQL

This SQL is a requirement for the Service to work properly. Since I'm using Dapper, you need 
a Postgres database with the following SQL tables: 

```sql
CREATE TABLE "HowlDev.User" (
  id int PRIMARY KEY GENERATED ALWAYS AS IDENTITY NOT NULL,
  accountName varchar(200) UNIQUE NOT NULL, 
  passHash varchar(200) NOT NULL, 
  email varchar(200) NULL, 
  displayName varchar(80) NULL,
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

## Changelog

0.8 (5/15/25)

- Init