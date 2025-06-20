namespace AccountAuthenticator;

/// <summary>
/// Configure certain parts of your middleware, such as un-authenticated paths, and (optionally)
/// the expiration dates of keys and when you want to re-validate their key for longer usage. 
/// </summary>
public class IDMiddlewareConfig {
    /// <summary>
    /// Set to the list of paths you want the middleware (Identity Middleware) 
    /// to exclude authorization.
    /// </summary>
    public List<string> Paths { get; set; } = new List<string>();

    /// <summary>
    /// If not null, the middleware will only check paths that start with this 
    /// path. For example, in some projects, all API calls start with <c>/api</c>, so adding 
    /// that will only check paths that start with <c>/api</c>. 
    /// </summary>
    public string? Whitelist { get; set; } = null;

    /// <summary>
    /// Set to the timespan that API keys are valid for. <c>Null</c> enables no time validation 
    /// (not recommended). 
    /// </summary>
    public TimeSpan? ExpirationDate { get; set; } = null;

    /// <summary>
    /// If set to <c>null</c>, does nothing. Otherwise, set it to a timespan so if their key is still 
    /// valid, reset the expiration date for their API key. 
    /// </summary>
    public TimeSpan? ReValidationDate { get; set; } = null;
}
