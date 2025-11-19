namespace AccountAuthenticator;

public class Account {
    public Guid Id { get; set; }
    public string AccountName { get; set; } = "Default Account Name";
    public int Role { get; set; }
}