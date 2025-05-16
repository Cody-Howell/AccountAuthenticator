namespace AccountAuthenticator;

/// <summary>
/// (Required) Configure certain parts of your middleware, such as un-authenticated paths, and (optionally)
/// the expiration dates of keys and when you want to re-validate their key for longer usage. 
/// </summary>
public interface IIDMiddlewareConfig {
    /// <summary>
    /// Set to the list of paths you want the middleware (Identity Middleware) 
    /// to exclude authorization.
    /// </summary>
    List<string> Paths { get; }

    /// <summary>
    /// Set to the timespan that API keys are valid for. <c>Null</c> enables no time validation 
    /// (not recommended). 
    /// </summary>
    TimeSpan? ExpirationDate { get; }

    /// <summary>
    /// If set to <c>null</c>, does nothing. Otherwise, set it to a timespan so if their key is still 
    /// valid, reset the expiration date for their API key. 
    /// </summary>
    TimeSpan? ReValidationDate { get; }
}
