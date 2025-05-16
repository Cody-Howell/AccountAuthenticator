using Dapper;
using System.Data;
using System.Diagnostics.CodeAnalysis;

namespace AccountAuthenticator;

/// <summary>
/// Service implementation to handle the database. Runs through Dapper.
/// </summary>
public class AuthService(IDbConnection conn) {
    /// <summary>
    /// Adds a new user if one doesn't already exist and throws an error if they do. Should 
    /// only be used in the sign-up process.
    /// </summary>
    /// <exception cref="ArgumentException"></exception>
    public void AddUser(string accountName, string defaultPassword = "password") {
        string passHash = StringHelper.CustomHash(defaultPassword);
        var AddUser = "insert into \"HowlDev.User\" (accountName, passHash, role) values (@accountName, @passHash, 0)";
        try {
            conn.Execute(AddUser, new { accountName, passHash });
        } catch {
            throw new ArgumentException("Account name already exists.");
        }
    }

    /// <summary>
    /// Adds a new line to the API key table.
    /// </summary>
    /// <returns>API key</returns>
    public string NewSignIn(string accountName) {
        string newApiKey = StringHelper.GenerateRandomString(20);
        DateTime now = DateTime.Now;

        var addValidation = "insert into \"HowlDev.Key\" (accountId, apiKey, validatedOn) values (@accountName, @newApiKey, @now)";
        conn.Execute(addValidation, new { accountName, newApiKey, now });

        return newApiKey;
    }

    /// <summary>
    /// <c>For Debug Only</c>, I wouldn't reccommend assigning this an endpoint. Returns all users sorted by 
    /// ID. 
    /// </summary>
    public IEnumerable<Account> GetAllUsers() {
        var GetUsers = "select p.id, p.accountName, p.displayName, p.email, p.role from \"HowlDev.User\" p order by 1";
        try {
            return conn.Query<Account>(GetUsers);
        } catch {
            return [];
        }
    }

    /// <summary>
    /// Returns the user object from the given email. Throws an exception if the user does not exist.
    /// </summary>
    public Account GetUser(string email) {
        var GetUsers = "select p.id, p.accountName, p.email, p.displayName, p.role from \"HowlDev.User\" p where email = @email";
        return conn.QuerySingle<Account>(GetUsers, new { email });
    }

    /// <summary>
    /// You can decide whether or not the returned date is valid (if you want expiration dates). 
    /// Throws an exception if no API key exists in the table. 
    /// </summary>
    /// <param name="email">Email address used</param>
    /// <param name="key">API Key</param>
    /// <returns>Null or DateTime</returns>
    /// <exception cref="Exception"></exception>
    public DateTime IsValidApiKey(string accountName, string key) {
        var validKey = "select k.validatedon from \"HowlDev.Key\" k where accountId = @accountName and apiKey = @key";
        return conn.QuerySingle<DateTime>(validKey, new { accountName, key });
    }

    /// <summary>
    /// Returns True if the username and password match what's stored in the database. This 
    /// handles errors thrown by invalid users and simply returns False.
    /// </summary>
    /// <returns>If the hashed password equals the stored hash</returns>
    public bool IsValidUserPass(string accountName, string password) {
        string hashedPassword = StringHelper.CustomHash(password);
        var pass = "select p.passHash from \"HowlDev.User\" p where accountName = @accountName";
        try {
            string storedPassword = conn.QuerySingle<string>(pass, new { accountName });
            return storedPassword == hashedPassword;
        } catch {
            return false;
        }
    }

    /// <summary>
    /// Updates the api key with the current DateTime value. This allows recently 
    /// signed-in users to continue being signed in on their key. It's primarily 
    /// used by my IdentityMiddleware and not recommended you use it on its own.
    /// </summary>
    public void ReValidate(string accountId, string key) {
        string time = DateTime.Now.ToUniversalTime().ToString("u");
        var validate = $"update \"HowlDev.Key\" hdk set validatedon = '{time}' where accountId = @accountId and apiKey = @key";
        conn.Execute(validate, new { accountId, key });
    }

    /// <summary>
    /// Updates the user's password in the table. Does not affect any of the API keys currently
    /// entered. 
    /// </summary>
    public void UpdatePassword(string accountName, string newPassword) {
        string newHash = StringHelper.CustomHash(newPassword);
        var pass = "update \"HowlDev.User\" p set passHash = @newHash where accountName = @accountName";
        conn.Execute(pass, new { accountName, newHash });
    }

    /// <summary>
    /// Deletes all sign-in records by the user and their place in the User table.
    /// </summary>
    public void DeleteUser(string accountId) {
        GlobalSignOut(accountId);

        var removeUser = "delete from \"HowlDev.User\" where accountName = @accountId";
        conn.Execute(removeUser, new { accountId });
    }

    /// <summary>
    /// Signs a user out globally (all keys are deleted), such as in the instance 
    /// of someone else gaining access to their account.
    /// </summary>
    public void GlobalSignOut(string accountId) {
        var removeKeys = "delete from \"HowlDev.Key\" where accountId = @accountId";
        conn.Execute(removeKeys, new { accountId });
    }

    /// <summary>
    /// Sign out on an individual device by passing the key you want signed out. 
    /// </summary>
    public void KeySignOut(string accountId, string key) {
        var removeKey = "delete from \"HowlDev.Key\" where accountId = @accountId and apiKey = @key";
        conn.Execute(removeKey, new { accountId, key });
    }

    /// <summary>
    /// Given the TimeSpan, remove keys from any user that are older than that length.
    /// </summary>
    public void ExpiredKeySignOut(TimeSpan length) {
        DateTime expirationTime = DateTime.Now - length;
        var removeKey = "delete from \"HowlDev.Key\" where validatedOn < @expirationTime";
        conn.Execute(removeKey, new { expirationTime });
    }
}