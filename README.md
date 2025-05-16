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
unique across all users), a password hash, and an optional display name and email. In the future, I might enable 
email-password-reset emails to be sent and generate an HTML page to show the user, but my primary solution 
is that the Admin can reset their password to "password", then they can get back in and change their password. 

Of course, I still have many of the features from the Email auth, with key re-enabling, single sign-out, global 
sign-out, and validation checks. It should feel somewhat similar to that library, just using a different mechanism. 

## Initial SQL

```sql
CREATE TABLE "HowlDev.User" (
  id int PRIMARY KEY GENERATED ALWAYS AS IDENTITY NOT NULL,
  accountName varchar(200) UNIQUE NOT NULL, 
  email varchar(200) NULL, 
  displayName varchar(80) NULL,
  role int4 NOT NULL
);

CREATE TABLE "HowlDev.Key" (
  id int PRIMARY KEY GENERATED ALWAYS AS IDENTITY NOT NULL,
  userId int references "HowlDev.User" (id) NOT NULL, 
  apiKey varchar(20) NOT NULL,
  validatedOn timestamp NOT NULL
);
```