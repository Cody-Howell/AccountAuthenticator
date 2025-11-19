using Microsoft.Extensions.Configuration;
using Npgsql;
using System;
using System.Collections.Generic;
using System.Data;

namespace AccountAuthenticator;

/// <summary>
/// DbConnector is an AI-assisted class that handles connection opening and closing, allowing 
/// multi-threaded operations. Prior to this, all AuthService calls were single-threaded. 
/// See comments/examples for the two primary methods. This is expected
/// to be used as a Singleton reference, like the following: 
/// <code>
/// builder.Services.AddSingleton&lt;DbConnector&gt;();
/// </code>
/// </summary>
public class DbConnector {
    private readonly string _connectionString;

    /// <summary>
    /// Do not call directly. Use DependencyInjection for this. 
    /// </summary>
    public DbConnector(IConfiguration config) {
        _connectionString = config.GetConnectionString("PostgresConnection") ?? throw new Exception($"Missing connection string for config: ConnectionStrings__PostgresConnection");
    }

    /// <summary>
    /// This method has a return type. It's designed to write methods like properties: 
    /// <code>
    /// public Task&lt;Account&gt; GetUserAsync(string account) =>
    ///     conn.WithConnectionAsync(async conn => {
    ///         var GetUsers = "select p.id, p.accountName, p.role from \"HowlDev.User\" p where accountName = @account";
    ///         return await conn.QuerySingleAsync&lt;Account&gt;(GetUsers, new { account });
    ///     }
    /// );
    /// </code>
    /// </summary>
    public async Task<T> WithConnectionAsync<T>(Func<NpgsqlConnection, Task<T>> action) {
        await using var conn = new NpgsqlConnection(_connectionString);
        return await action(conn);
    }

    /// <summary>
    /// This method does not have a return type. 
    /// It's designed to write methods like properties: 
    /// <code>
    /// public Task GlobalSignOutAsync(string accountId) =>
    ///     conn.WithConnectionAsync(async conn => {
    ///         var removeKeys = "delete from \"HowlDev.Key\" where accountId = @accountId";
    ///         await conn.ExecuteAsync(removeKeys, new { accountId });
    ///     }
    /// );
    /// </code>
    /// </summary>
    public async Task WithConnectionAsync(Func<NpgsqlConnection, Task> action) {
        await using var conn = new NpgsqlConnection(_connectionString);
        await action(conn);
    }

    /// <summary>
    /// This method has a return type. It's designed to write methods like properties: 
    /// <code>
    /// public Account GetUser(string account) =>
    ///     conn.WithConnection(conn => {
    ///         var GetUsers = "select p.id, p.accountName, p.role from \"HowlDev.User\" p where accountName = @account";
    ///         return conn.QuerySingle&lt;Account&gt;(GetUsers, new { account });
    ///     }
    /// );
    /// </code>
    /// </summary>
    public T WithConnection<T>(Func<NpgsqlConnection, T> action) {
        using var conn = new NpgsqlConnection(_connectionString);
        return action(conn);
    }

    /// <summary>
    /// This method does not have a return type. 
    /// It's designed to write methods like properties: 
    /// <code>
    /// public void GlobalSignOut(string accountId) =>
    ///     conn.WithConnection(conn => {
    ///         var removeKeys = "delete from \"HowlDev.Key\" where accountId = @accountId";
    ///         conn.Execute(removeKeys, new { accountId });
    ///     }
    /// );
    /// </code>
    /// </summary>
    public void WithConnection(Action<NpgsqlConnection> action) {
        using var conn = new NpgsqlConnection(_connectionString);
        action(conn);
    }
}