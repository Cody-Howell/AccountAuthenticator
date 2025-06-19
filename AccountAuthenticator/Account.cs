namespace AccountAuthenticator;

public class Account {
    public Guid Id { get; set; }
    public string AccountName { get; set; } = "Default Account Name";
    public string? Email { get; set; }
    public string? DisplayName { get; set; } 
    public int Role { get; set; }
}
