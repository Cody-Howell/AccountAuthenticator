using Dapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AccountAuthenticator;
public partial class AuthService {

    #region User Creation/Validation
    /// <summary>
    /// Adds a new user if one doesn't already exist and throws an error if they do. Should 
    /// only be used in the sign-up process.
    /// </summary>
    /// <exception cref="ArgumentException"></exception>
    public void AddUser(string accountName, string defaultPassword = "password", int defaultRole = 0) =>
        conn.WithConnection(conn => {
            string passHash = StringHelper.CustomHash(defaultPassword);
            Guid guid = Guid.NewGuid();
            var AddUser = "insert into \"HowlDev.User\" values (@guid, @accountName, @passHash, @defaultRole)";
            try {
                conn.Execute(AddUser, new { guid, accountName, passHash, defaultRole });
            } catch {
                throw new ArgumentException("Account name already exists.");
            }
        }
    );

    /// <summary>
    /// Adds a new line to the API key table.
    /// </summary>
    /// <returns>API key</returns>
    public string NewSignIn(string accountName) =>
        conn.WithConnection(conn => {
            string newApiKey = StringHelper.GenerateRandomString(20);
            DateTime now = DateTime.Now;

            var addValidation = "insert into \"HowlDev.Key\" (accountId, apiKey, validatedOn) values (@accountName, @newApiKey, @now)";
            conn.Execute(addValidation, new { accountName, newApiKey, now });

            return newApiKey;
        }
    );

    /// <summary>
    /// <c>For Debug Only</c>, I wouldn't reccommend assigning this an endpoint. Returns all users sorted by 
    /// ID. 
    /// </summary>
    public IEnumerable<Account> GetAllUsers() =>
        conn.WithConnection(conn => {
            var GetUsers = "select p.id, p.accountName, p.role from \"HowlDev.User\" p";
            try {
                return conn.Query<Account>(GetUsers);
            } catch {
                return [];
            }
        }
    );

    /// <summary>
    /// Returns the user object from the given account. Throws an exception if the user does not exist.
    /// </summary>
    public Account GetUser(string account) =>
        conn.WithConnection(conn => {
            return new Account {
                Id = GetGuid(account),
                AccountName = account,
                Role = GetRole(account)
            };
        }
    );
    #endregion

    #region Validation
    /// <summary>
    /// You can decide whether or not the returned date is valid (if you want expiration dates). 
    /// Throws an exception if no API key exists in the table. 
    /// </summary>
    /// <param name="accountName">Account used</param>
    /// <param name="key">API Key</param>
    /// <returns>Null or DateTime</returns>
    /// <exception cref="Exception"></exception>
    public DateTime IsValidApiKey(string accountName, string key) =>
        conn.WithConnection(conn => {
            var validKey = "select k.validatedon from \"HowlDev.Key\" k where accountId = @accountName and apiKey = @key";
            return conn.QuerySingle<DateTime>(validKey, new { accountName, key });
        }
    );

    /// <summary>
    /// Returns True if the username and password match what's stored in the database. This 
    /// handles errors thrown by invalid users and simply returns False.
    /// </summary>
    /// <returns>If the hashed password equals the stored hash</returns>
    public bool IsValidUserPass(string accountName, string password) =>
        conn.WithConnection(conn => {
            string hashedPassword = StringHelper.CustomHash(password);
            var pass = "select p.passHash from \"HowlDev.User\" p where accountName = @accountName";
            try {
                string storedPassword = conn.QuerySingle<string>(pass, new { accountName });
                return storedPassword == hashedPassword;
            } catch {
                return false;
            }
        }
    );

    /// <summary>
    /// Updates the api key with the current DateTime value. This allows recently 
    /// signed-in users to continue being signed in on their key. It's primarily 
    /// used by my IdentityMiddleware and not recommended you use it on its own.
    /// </summary>
    public void ReValidate(string accountId, string key) =>
        conn.WithConnection(conn => {
            string time = DateTime.Now.ToUniversalTime().ToString("u");
            var validate = $"update \"HowlDev.Key\" hdk set validatedon = '{time}' where accountId = @accountId and apiKey = @key";
            conn.Execute(validate, new { accountId, key });
        }
    );
    #endregion

    #region Updates
    /// <summary>
    /// Updates the user's password in the table. Does not affect any of the API keys currently
    /// entered. 
    /// </summary>
    public void UpdatePassword(string accountName, string newPassword) =>
        conn.WithConnection(conn => {
            string newHash = StringHelper.CustomHash(newPassword);
            var pass = "update \"HowlDev.User\" p set passHash = @newHash where accountName = @accountName";
            conn.Execute(pass, new { accountName, newHash });
        }
    );

    /// <summary>
    /// Updates the user's role in the table. Does not affect any current keys.
    /// Does update the lookup dictionary with the new role. 
    /// </summary>
    public void UpdateRole(string accountName, int newRole) =>
        conn.WithConnection(conn => {
            var role = "update \"HowlDev.User\" p set role = @newRole where accountName = @accountName";
            conn.Execute(role, new { accountName, newRole });
            roleLookup[accountName] = newRole;
        }
    );
    #endregion

    #region Deletion/Sign Out
    /// <summary>
    /// Deletes all sign-in records by the user and their place in the User table.
    /// </summary>
    public void DeleteUser(string accountId) =>
        conn.WithConnection(conn => {
            GlobalSignOut(accountId);

            var removeUser = "delete from \"HowlDev.User\" where accountName = @accountId";
            conn.Execute(removeUser, new { accountId });
        }
    );

    /// <summary>
    /// Signs a user out globally (all keys are deleted), such as in the instance 
    /// of someone else gaining access to their account.
    /// </summary>
    public void GlobalSignOut(string accountId) =>
        conn.WithConnection(conn => {
            var removeKeys = "delete from \"HowlDev.Key\" where accountId = @accountId";
            conn.Execute(removeKeys, new { accountId });
        }
    );

    /// <summary>
    /// Sign out on an individual device by passing the key you want signed out. 
    /// </summary>
    public void KeySignOut(string accountId, string key) =>
        conn.WithConnection(conn => {
            var removeKey = "delete from \"HowlDev.Key\" where accountId = @accountId and apiKey = @key";
            conn.Execute(removeKey, new { accountId, key });
        }
    );

    /// <summary>
    /// Given the TimeSpan, remove keys from any user that are older than that length.
    /// </summary>
    public void ExpiredKeySignOut(TimeSpan length) =>
        conn.WithConnection(conn => {
            DateTime expirationTime = DateTime.Now - length;
            var removeKey = "delete from \"HowlDev.Key\" where validatedOn < @expirationTime";
            conn.Execute(removeKey, new { expirationTime });
        }
    );
    #endregion

    #region Search
    /// <summary>
    /// Returns the Guid of a given account name. Has an internal dictionary to reduce 
    /// database calls and enable quick lookup.
    /// </summary>
    public Guid GetGuid(string account) =>
        conn.WithConnection(conn => {
            if (guidLookup.ContainsKey(account)) {
                return guidLookup[account];
            } else {
                string guid = "select id from \"HowlDev.User\" where accountName = @account";
                Guid theirGuid = conn.QuerySingle<Guid>(guid, new { account });
                guidLookup.Add(account, theirGuid);
                return theirGuid;
            }
        }
    );

    /// <summary>
    /// Returns the Role of a given account name. Has an internal dictionary to reduce database calls
    /// and enable quick lookups. 
    /// </summary>
    public int GetRole(string account) =>
        conn.WithConnection(conn => {
            if (roleLookup.ContainsKey(account)) {
                return roleLookup[account];
            } else {
                string role = "select role from \"HowlDev.User\" where accountName = @account";
                int theirRole = conn.QuerySingle<int>(role, new { account });
                roleLookup.Add(account, theirRole);
                return theirRole;
            }
        }
    );

    /// <summary>
    /// Retrieves the current number of sessions for a given user. 
    /// </summary>
    public int GetCurrentSessionCount(string account) =>
        conn.WithConnection(conn => {
            string connCount = "select count(*) from \"HowlDev.Key\" where accountId = @account";
            return conn.QuerySingle<int>(connCount, new { account });
        });
    #endregion
}
