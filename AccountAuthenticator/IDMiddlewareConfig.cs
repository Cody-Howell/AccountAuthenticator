namespace AccountAuthenticator;

/// <summary>
/// Configure certain parts of your middleware, such as un-authenticated paths, and (optionally)
/// the expiration dates of keys and when you want to re-validate their key for longer usage. 
/// </summary>
public class IDMiddlewareConfig {
    /// <summary>
    /// Set to the list of paths that you want the middleware  
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
    /// Set to the timespan that API keys are valid for. <c>Null</c> enables no time validation. 
    /// </summary>
    public TimeSpan? ExpirationDate { get; set; } = null;

    /// <summary>
    /// If set to <c>null</c>, does nothing. Otherwise, set it to a timespan so if their key is still 
    /// valid, reset the expiration date for their API key. 
    /// </summary>
    public TimeSpan? ReValidationDate { get; set; } = null;

    /// <summary>
    /// Enables all levels of Traces, Debug, Information, and Error 
    /// in the IdentityMiddleware. Set different logging levels in appsettings.json.
    /// </summary>
    public bool EnableLogging { get; set; } = false;

    /// <summary>
    /// Removes detailed error messages with invalid headers. As you shouldn't broadcast 
    /// what headers are needed to bypass an authentication middleware, this should be disabled 
    /// in production (and after you get your frontend API calls set up). 
    /// </summary>
    public bool DisableHeaderInfo { get; set; } = false;
}