CREATE TABLE "HowlDev.User" (
  id UUID PRIMARY KEY,
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
