using System.Globalization;
using System.Net.Http.Json;

namespace MerkleAudit.Demo;

/// <summary>
/// Writes a deterministic, synthetic hospital-records audit trail through the public API. Every value is derived from
/// the entry number, so two runs produce identical rows (the golden test relies on it). No real people or data.
/// </summary>
public static class DemoSeeder
{
    private static readonly string[] Actors = ["dr.ayse.k", "dr.mehmet.t", "nurse.elif.s", "clerk.burak.a", "admin.zeynep.o", "svc.lab-sync"];
    private static readonly string[] Actions = ["record.read", "record.update", "prescription.create", "lab.result.view", "export.pdf", "consent.update"];

    public static object Entry(int n) => new
    {
        actor = Actors[n % Actors.Length],
        action = Actions[(n / 2) % Actions.Length],
        resource = string.Create(CultureInfo.InvariantCulture, $"patient/P-{(n * 37) % 1000:D6}"),
        payload = new
        {
            ip = string.Create(CultureInfo.InvariantCulture, $"10.20.{n % 7}.{(n * 13) % 250 + 1}"),
            reason = n % 5 == 0 ? "emergency-access" : "treatment",
            n,
        },
    };

    /// <summary>
    /// Appends <paramref name="count"/> entries in batches of <paramref name="publishEvery"/>, and after each batch waits
    /// until a signed head covers it, so the log ends with one signed head per batch.
    /// </summary>
    public static async Task SeedAsync(HttpClient http, string apiKey, int count, int publishEvery, Func<long, Task> ensureHeadAsync, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(ensureHeadAsync);
        for (var start = 0; start < count; start += publishEvery)
        {
            var batch = Enumerable.Range(start, Math.Min(publishEvery, count - start)).Select(Entry).ToArray();
            using var request = new HttpRequestMessage(HttpMethod.Post, "api/v1/entries/batch") { Content = JsonContent.Create(batch) };
            request.Headers.Add("X-Api-Key", apiKey);
            using var response = await http.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();
            await ensureHeadAsync(start + batch.Length);
        }
    }

    /// <summary>Polls the latest signed head until it covers <paramref name="size"/> (the compose server publishes every second).</summary>
    public static async Task WaitForHeadAsync(HttpClient http, long size, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(http);
        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (true)
        {
            using var response = await http.GetAsync(new Uri("api/v1/sth", UriKind.Relative), cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                var head = await response.Content.ReadFromJsonAsync<Verifier.TreeHeadDto>(cancellationToken);
                if (head is not null && head.TreeSize >= size)
                {
                    return;
                }
            }

            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException($"No signed tree head covering size {size} within 60 s.");
            }

            await Task.Delay(200, cancellationToken);
        }
    }
}
