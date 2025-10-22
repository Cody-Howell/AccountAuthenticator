namespace AccountAuthenticator;

public interface IAuthService {
    Task AddUserAsync(string accountName, string defaultPassword, int defaultRole);
    Task DeleteUserAsync(string accountId);
    Task ExpiredKeySignOutAsync(TimeSpan length);
    Task<IEnumerable<Account>> GetAllUsersAsync();
    Task<int> GetCurrentSessionCountAsync(string account);
    Task<Guid> GetGuidAsync(string account);
    Task<int> GetRoleAsync(string account);
    Task<Account> GetUserAsync(string account);
    Task GlobalSignOutAsync(string accountId);
    Task<DateTime> IsValidApiKeyAsync(string accountName, string key);
    Task<bool> IsValidUserPassAsync(string accountName, string password);
    Task KeySignOutAsync(string accountId, string key);
    Task<string> NewSignInAsync(string accountName);
    Task ReValidateAsync(string accountId, string key);
    Task UpdatePasswordAsync(string accountName, string newPassword);
    Task UpdateRoleAsync(string accountName, int newRole);
    void AddUser(string accountName, string defaultPassword, int defaultRole);
    void DeleteUser(string accountId);
    void ExpiredKeySignOut(TimeSpan length);
    IEnumerable<Account> GetAllUsers();
    int GetCurrentSessionCount(string account);
    Guid GetGuid(string account);
    int GetRole(string account);
    Account GetUser(string account);
    void GlobalSignOut(string accountId);
    DateTime IsValidApiKey(string accountName, string key);
    bool IsValidUserPass(string accountName, string password);
    void KeySignOut(string accountId, string key);
    string NewSignIn(string accountName);
    void ReValidate(string accountId, string key);
    void UpdatePassword(string accountName, string newPassword);
    void UpdateRole(string accountName, int newRole);
}