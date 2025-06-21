using Microsoft.AspNetCore.Mvc.Testing;
using System.Net.Http.Json;

namespace AccountAuthenticator.IntegrationTests;

public class BaseIDMiddlewareTests {
    [ClassDataSource<WebAppFactory>(Shared = SharedType.PerClass)]
    public required WebAppFactory WebAppFactory { get; init; }

    private List<string> props = new();

    [Test]
    [NotInParallel(Order = 1)]
    public async Task HealthCheck() {
        HttpClient client = WebAppFactory.CreateClient();
        string result = await client.GetStringAsync("/health");
        await Assert.That(result).IsEqualTo("Hello");

        var response2 = await client.GetAsync("/users");
        List<Account> accounts = await response2.Content.ReadFromJsonAsync<List<Account>>()
            ?? throw new Exception("List should not be null");
        await Assert.That(accounts.Count).IsEqualTo(0);
    }

    [Test]
    [NotInParallel(Order = 2)]
    public async Task ProperResponseOfNoHeaders() {
        HttpClient client = WebAppFactory.CreateClient();

        var response = client.GetAsync("/user?user=Cody");
        await Assert.That(await response.Result.Content.ReadAsStringAsync())
            .IsEqualTo("Unauthorized: Missing header(s).\nRequires an \"Account-Auth-Account\" and \"Account-Auth-ApiKey\" header.");
    }

    //[Test]
    //[NotInParallel(Order = 3)]
    //public async Task CanCreateAndSignInAccount() {
    //    HttpClient client = WebAppFactory.CreateClient();

    //    await client.PostAsync("/user?accountName=Cody", null);

    //    SignIn obj = new SignIn { user = "Cody", pass = "password" };
    //    var response1 = await client.PostAsJsonAsync("/user/signin", obj);
    //    string key = await response1.Content.ReadAsStringAsync();
    //    props.Add(key);

    //    await Assert.That(key.Length).IsEqualTo(20);

    //    var response2 = await client.GetAsync("/users");
    //    List<Account> accounts = await response2.Content.ReadFromJsonAsync<List<Account>>()
    //        ?? throw new Exception("List should not be null");
    //    await Assert.That(accounts.Count).IsEqualTo(1);
    //}

    //[Test]
    //[NotInParallel(Order = 4)]
    //public async Task CanReadValidGuidAndRole() {
    //    HttpClient client = WebAppFactory.CreateClient();
    //    client.DefaultRequestHeaders.Add("Account-Auth-Account", "Cody");
    //    client.DefaultRequestHeaders.Add("Account-Auth-Key", props[0]);

    //    var response1 = await client.GetAsync("/user/valid");
    //    await Assert.That(response1.StatusCode).IsEqualTo(System.Net.HttpStatusCode.OK);

    //    var response2 = await client.GetAsync("/user/guid");
    //    Guid guid = new (await response2.Content.ReadAsStringAsync());
    //    await Assert.That(guid).IsNotNull();

    //    var response3 = await client.GetAsync("/user/role");
    //    int role = Convert.ToInt32(await response3.Content.ReadAsStringAsync());
    //    await Assert.That(role).IsEqualTo(0);
    //}
}