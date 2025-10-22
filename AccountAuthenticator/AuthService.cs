using Dapper;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.Data;

namespace AccountAuthenticator;

/// <summary>
/// Service implementation to handle the database. Runs through Dapper.
/// </summary>
public partial class AuthService(IConfiguration config, ILogger<AuthService> logger) : IAuthService {
    private Dictionary<string, Guid> guidLookup = new();
    private Dictionary<string, int> roleLookup = new();
    private DbConnector conn = new DbConnector(config);

    #region User Creation/Validation
    /// <summary>
    /// Adds a new user if one doesn't already exist and throws an error if they do. Should 
    /// only be used in the sign-up process.
    /// </summary>
    /// <exception cref="ArgumentException"></exception>
    public Task AddUserAsync(string accountName, string defaultPassword = "password", int defaultRole = 0) =>
        conn.WithConnectionAsync(async conn => {
            string passHash = Argon2Helper.HashPassword(defaultPassword);
            Guid guid = Guid.NewGuid();
            var AddUser = "insert into \"HowlDev.User\" values (@guid, @accountName, @passHash, @defaultRole)";
            try {
                await conn.ExecuteAsync(AddUser, new { guid, accountName, passHash, defaultRole });
            } catch {
                throw new ArgumentException("Account name already exists.");
            }
        }
    );

    /// <summary>
    /// Adds a new line to the API key table.
    /// </summary>
    /// <returns>API key</returns>
    public Task<string> NewSignInAsync(string accountName) =>
        conn.WithConnectionAsync(async conn => {
            string newApiKey = StringHelper.GenerateRandomString(20);
            DateTime now = DateTime.Now;

            var addValidation = "insert into \"HowlDev.Key\" (accountId, apiKey, validatedOn) values (@accountName, @newApiKey, @now)";
            await conn.ExecuteAsync(addValidation, new { accountName, newApiKey, now });

            return newApiKey;
        }
    );

    /// <summary>
    /// <c>For Debug Only</c>, I wouldn't reccommend assigning this an endpoint. Returns all users sorted by 
    /// ID. 
    /// </summary>
    public Task<IEnumerable<Account>> GetAllUsersAsync() =>
        conn.WithConnectionAsync(async conn => {
            var GetUsers = "select p.id, p.accountName, p.role from \"HowlDev.User\" p order by 1";
            try {
                return await conn.QueryAsync<Account>(GetUsers);
            } catch {
                return [];
            }
        }
    );

    /// <summary>
    /// Returns the user object from the given account. Throws an exception if the user does not exist.
    /// </summary>
    public Task<Account> GetUserAsync(string account) =>
        conn.WithConnectionAsync(async conn => {
            return new Account {
                Id = await GetGuidAsync(account),
                AccountName = account,
                Role = await GetRoleAsync(account)
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
    public Task<DateTime> IsValidApiKeyAsync(string accountName, string key) =>
        conn.WithConnectionAsync(async conn => {
            var validKey = "select k.validatedon from \"HowlDev.Key\" k where accountId = @accountName and apiKey = @key";
            return await conn.QuerySingleAsync<DateTime>(validKey, new { accountName, key });
        }
    );

    /// <summary>
    /// Returns True if the username and password match what's stored in the database. This 
    /// handles errors thrown by invalid users and simply returns False.
    /// </summary>
    /// <returns>If the hashed password equals the stored hash</returns>
    public Task<bool> IsValidUserPassAsync(string accountName, string password) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered IsValidUserPassAsync.");
            try {
                var pass = "select p.passHash from \"HowlDev.User\" p where accountName = @accountName";
                string storedPassword = await conn.QuerySingleAsync<string>(pass, new { accountName });
                return Argon2Helper.VerifyPassword(storedPassword, password);
            } catch (Exception e) {
                logger.LogWarning("Error: {a}", e);
                return false;
            }
        }
    );

    /// <summary>
    /// Updates the api key with the current DateTime value. This allows recently 
    /// signed-in users to continue being signed in on their key. It's primarily 
    /// used by my IdentityMiddleware and not recommended you use it on its own.
    /// </summary>
    public Task ReValidateAsync(string accountId, string key) =>
        conn.WithConnectionAsync(async conn => {
            string time = DateTime.Now.ToUniversalTime().ToString("u");
            var validate = $"update \"HowlDev.Key\" hdk set validatedon = '{time}' where accountId = @accountId and apiKey = @key";
            await conn.ExecuteAsync(validate, new { accountId, key });
        }
    );
    #endregion

    #region Updates
    /// <summary>
    /// Updates the user's password in the table. Does not affect any of the API keys currently
    /// entered. 
    /// </summary>
    public Task UpdatePasswordAsync(string accountName, string newPassword) =>
        conn.WithConnectionAsync(async conn => {
            string newHash = Argon2Helper.HashPassword(newPassword);
            var pass = "update \"HowlDev.User\" p set passHash = @newHash where accountName = @accountName";
            await conn.ExecuteAsync(pass, new { accountName, newHash });
        }
    );

    /// <summary>
    /// Updates the user's role in the table. Does not affect any current keys.
    /// Does update the lookup dictionary with the new role. 
    /// </summary>
    public Task UpdateRoleAsync(string accountName, int newRole) =>
        conn.WithConnectionAsync(async conn => {
            var role = "update \"HowlDev.User\" p set role = @newRole where accountName = @accountName";
            await conn.ExecuteAsync(role, new { accountName, newRole });
            roleLookup[accountName] = newRole;
        }
    );
    #endregion

    #region Deletion/Sign Out
    /// <summary>
    /// Deletes all sign-in records by the user and their place in the User table.
    /// </summary>
    public Task DeleteUserAsync(string accountId) =>
        conn.WithConnectionAsync(async conn => {
            await GlobalSignOutAsync(accountId);

            var removeUser = "delete from \"HowlDev.User\" where accountName = @accountId";
            await conn.ExecuteAsync(removeUser, new { accountId });
        }
    );

    /// <summary>
    /// Signs a user out globally (all keys are deleted), such as in the instance 
    /// of someone else gaining access to their account.
    /// </summary>
    public Task GlobalSignOutAsync(string accountId) =>
        conn.WithConnectionAsync(async conn => {
            var removeKeys = "delete from \"HowlDev.Key\" where accountId = @accountId";
            await conn.ExecuteAsync(removeKeys, new { accountId });
        }
    );

    /// <summary>
    /// Sign out on an individual device by passing the key you want signed out. 
    /// </summary>
    public Task KeySignOutAsync(string accountId, string key) =>
        conn.WithConnectionAsync(async conn => {
            var removeKey = "delete from \"HowlDev.Key\" where accountId = @accountId and apiKey = @key";
            await conn.ExecuteAsync(removeKey, new { accountId, key });
        }
    );

    /// <summary>
    /// Given the TimeSpan, remove keys from any user that are older than that length.
    /// </summary>
    public Task ExpiredKeySignOutAsync(TimeSpan length) =>
        conn.WithConnectionAsync(async conn => {
            DateTime expirationTime = DateTime.Now - length;
            var removeKey = "delete from \"HowlDev.Key\" where validatedOn < @expirationTime";
            await conn.ExecuteAsync(removeKey, new { expirationTime });
        }
    );
    #endregion

    #region Search
    /// <summary>
    /// Returns the Guid of a given account name. Has an internal dictionary to reduce 
    /// database calls and enable quick lookup.
    /// </summary>
    public Task<Guid> GetGuidAsync(string account) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered GetGuidAsync");
            if (guidLookup.ContainsKey(account)) {
                logger.LogDebug("GuidLookup contained key.");
                return guidLookup[account];
            } else {
                logger.LogDebug("GuidLookup did not contain the key.");
                string guid = "select id from \"HowlDev.User\" where accountName = @account";
                Guid theirGuid = await conn.QuerySingleAsync<Guid>(guid, new { account });
                guidLookup.Add(account, theirGuid);
                return theirGuid;
            }
        }
    );

    /// <summary>
    /// Returns the Role of a given account name. Has an internal dictionary to reduce database calls
    /// and enable quick lookups. 
    /// </summary>
    public Task<int> GetRoleAsync(string account) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered GetRoleAsync");
            if (roleLookup.ContainsKey(account)) {
                logger.LogDebug("RoleLookup contained key.");
                return roleLookup[account];
            } else {
                logger.LogDebug("RoleLookup did not contain the key.");
                string role = "select role from \"HowlDev.User\" where accountName = @account";
                int theirRole = await conn.QuerySingleAsync<int>(role, new { account });
                roleLookup.Add(account, theirRole);
                return theirRole;
            }
        }
    );

    /// <summary>
    /// Retrieves the current number of sessions for a given user. 
    /// </summary>
    public Task<int> GetCurrentSessionCountAsync(string account) =>
        conn.WithConnectionAsync(async conn => {
            logger.LogTrace("Entered GetCurrentSessionCountAsync");
            string connCount = "select count(*) from \"HowlDev.Key\" where accountId = @account";
            return await conn.QuerySingleAsync<int>(connCount, new { account });
        });
    #endregion
}