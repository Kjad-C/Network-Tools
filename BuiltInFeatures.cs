using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Built-in features and registration. Keep all feature implementations here (single canonical file).
/// Replace/extend placeholders with real implementations as needed.
/// </summary>
public static class BuiltInFeatureRegistration
{
    private static readonly HttpClient _http = new();

    public static void RegisterDefaults(FeatureManager manager)
    {
        // Core implemented features
        manager.Register(new PingFeature());
        manager.Register(new DnsLookupFeature());
        manager.Register(new HttpHeaderFeature());
        manager.Register(new ReverseDnsFeature());
        manager.Register(new CertificateInfoFeature());
        manager.Register(new SubdomainEnumerationFeature());
        manager.Register(new PortScannerFeature());
        manager.Register(new ShodanSearchFeature());
        manager.Register(new CertificateTransparencyFeature());
        manager.Register(new ZoneTransferAttemptFeature());
        manager.Register(new PassiveDnsFeature());
        manager.Register(new WhoisPlaceholderFeature());

        // Additional features with usable implementations
        manager.Register(new MxLookupFeature());
        manager.Register(new TxtLookupFeature());
        manager.Register(new DmarcCheckFeature());
        manager.Register(new DnssecCheckFeature());
        manager.Register(new AsnGeoIpFeature());
        manager.Register(new TracerouteFeature());
        manager.Register(new ReverseIpFeature());
        manager.Register(new CdnDetectFeature());
        manager.Register(new RobotsFetchFeature());
        manager.Register(new SitemapFetchFeature());
        manager.Register(new FaviconHashFeature());
        manager.Register(new TlsProbeFeature());
        manager.Register(new HstsCheckFeature());
        manager.Register(new OpenRedirectScanFeature());
        manager.Register(new SubdomainPermutationFeature());
        manager.Register(new CertIssuerSearchFeature());
        manager.Register(new WaybackLookupFeature());
        manager.Register(new RobotsSitemapAnalyzerFeature());
        manager.Register(new BannerGrabFeature());
        manager.Register(new HttpMethodsFeature());
        manager.Register(new DnsBruteForceFeature());
        manager.Register(new PtrSweepFeature());
        manager.Register(new TakeoverCheckFeature());
        manager.Register(new EmailHarvesterFeature());
        manager.Register(new BlacklistCheckPlaceholder());
        manager.Register(new ScreenshotPlaceholder());
        manager.Register(new MetadataExtractPlaceholder());
        manager.Register(new ImageReversePlaceholder());
    }

    // Small helper for DOH queries (Google DNS)
    internal static async Task<JsonDocument?> DohQueryAsync(string name, string type, CancellationToken ct)
    {
        try
        {
            var url = $"https://dns.google/resolve?name={WebUtility.UrlEncode(name)}&type={WebUtility.UrlEncode(type)}";
            using var res = await _http.GetAsync(url, ct);
            res.EnsureSuccessStatusCode();
            var s = await res.Content.ReadAsStringAsync(ct);
            return JsonDocument.Parse(s);
        }
        catch
        {
            return null;
        }
    }

    // Small helper to fetch JSON
    internal static async Task<JsonDocument?> GetJsonAsync(string url, CancellationToken ct)
    {
        try
        {
            using var res = await _http.GetAsync(url, ct);
            res.EnsureSuccessStatusCode();
            var s = await res.Content.ReadAsStringAsync(ct);
            return JsonDocument.Parse(s);
        }
        catch
        {
            return null;
        }
    }
}

#region Concrete implemented features (existing)

public class PingFeature : IFeature
{
    public string Id => "ping";
    public string Name => "Ping Host";
    public string Description => "Sends ICMP echo requests to a host";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Host to ping> ");
        var host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host)) { Console.WriteLine("No host."); return; }

        using var ping = new Ping();
        for (int i = 0; i < 4; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var reply = await ping.SendPingAsync(host, 2000);
                Console.WriteLine($"Reply from {reply.Address}: Status={reply.Status} Time={reply.RoundtripTime}ms TTL={reply.Options?.Ttl}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ping error: {ex.Message}");
            }
            await Task.Delay(500, cancellationToken);
        }
    }
}

public class DnsLookupFeature : IFeature
{
    public string Id => "dns.lookup";
    public string Name => "DNS Lookup";
    public string Description => "Resolves DNS A/AAAA records for a host.";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Domain to resolve> ");
        var host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host)) { Console.WriteLine("No host."); return; }

        try
        {
            var addrs = await Dns.GetHostAddressesAsync(host);
            foreach (var a in addrs) Console.WriteLine(a);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"DNS error: {ex.Message}");
        }
    }
}

public class HttpHeaderFeature : IFeature
{
    public string Id => "http.headers";
    public string Name => "Fetch HTTP Headers";
    public string Description => "Performs a GET and prints response headers.";
    public bool IsEnabled { get; set; } = true;

    private static readonly HttpClient _httpLocal = new();

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("URL> ");
        var url = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(url)) { Console.WriteLine("No URL."); return; }
        if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase)) url = "http://" + url;

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            using var res = await _httpLocal.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            Console.WriteLine($"Status: {(int)res.StatusCode} {res.ReasonPhrase}");
            foreach (var h in res.Headers) Console.WriteLine($"{h.Key}: {string.Join(", ", h.Value)}");
            foreach (var h in res.Content.Headers) Console.WriteLine($"{h.Key}: {string.Join(", ", h.Value)}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"HTTP error: {ex.Message}");
        }
    }
}

public class ReverseDnsFeature : IFeature
{
    public string Id => "dns.reverse";
    public string Name => "Reverse DNS";
    public string Description => "Attempts a reverse DNS lookup for an IPv4/IPv6 address.";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("IP address> ");
        var ip = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(ip)) { Console.WriteLine("No IP."); return; }

        try
        {
            var entries = await Dns.GetHostEntryAsync(ip);
            Console.WriteLine($"HostName: {entries.HostName}");
            foreach (var alias in entries.Aliases) Console.WriteLine($"Alias: {alias}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Reverse DNS error: {ex.Message}");
        }
    }
}

public class CertificateInfoFeature : IFeature
{
    public string Id => "tls.certinfo";
    public string Name => "Fetch TLS Certificate Info";
    public string Description => "Fetches server certificate (connects to :443) and prints basic info.";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Host (without port)> ");
        var host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host)) { Console.WriteLine("No host."); return; }

        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(host, 443);
            using var stream = client.GetStream();
            var ssl = new System.Net.Security.SslStream(stream, false, (a, b, c, d) => true);
            await ssl.AuthenticateAsClientAsync(host);
            var cert = new X509Certificate2(ssl.RemoteCertificate);
            Console.WriteLine($"Subject: {cert.Subject}");
            Console.WriteLine($"Issuer: {cert.Issuer}");
            Console.WriteLine($"Valid from: {cert.NotBefore} to {cert.NotAfter}");
            Console.WriteLine($"Thumbprint: {cert.Thumbprint}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Certificate error: {ex.Message}");
        }
    }
}

public class SubdomainEnumerationFeature : IFeature
{
    public string Id => "subdomain.enum";
    public string Name => "Subdomain Enumeration (brute)";
    public string Description => "Brute-forces common subdomain prefixes and resolves them via DNS.";
    public bool IsEnabled { get; set; } = true;

    private static readonly string[] DefaultWordlist = new[]
    {
        "www","mail","ftp","webmail","api","dev","test","ns1","ns2","smtp","blog","m","shop","staging"
    };

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Domain> ");
        var domain = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(domain)) { Console.WriteLine("No domain."); return; }

        Console.Write("Enter comma-separated prefixes to try or Enter to use default> ");
        var line = Console.ReadLine();
        var prefixes = string.IsNullOrWhiteSpace(line) ? DefaultWordlist : line.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        foreach (var p in prefixes)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var host = $"{p}.{domain}";
            try
            {
                var dnsTask = Dns.GetHostAddressesAsync(host);
                var completed = await Task.WhenAny(dnsTask, Task.Delay(3000, cancellationToken));
                if (completed == dnsTask)
                {
                    var addrs = await dnsTask;
                    if (addrs?.Length > 0)
                    {
                        Console.WriteLine($"{host} -> {string.Join(", ", addrs.Select(a => a.ToString()))}");
                    }
                }
            }
            catch
            {
                // ignore unresolved
            }
        }
    }
}

public class PortScannerFeature : IFeature
{
    public string Id => "port.scan";
    public string Name => "Port Scanner (TCP connect)";
    public string Description => "Attempts TCP connect to a range of ports to detect open ones.";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Host or IP> ");
        var host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host)) { Console.WriteLine("No host."); return; }

        Console.Write("Port range (e.g. 1-1024)> ");
        var range = Console.ReadLine()?.Trim() ?? "1-1024";
        if (!TryParseRange(range, out int start, out int end)) { Console.WriteLine("Invalid range."); return; }

        var open = new List<int>();
        for (int port = start; port <= end; port++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var tcp = new TcpClient();
            try
            {
                var connectTask = tcp.ConnectAsync(host, port);
                var completed = await Task.WhenAny(connectTask, Task.Delay(800, cancellationToken));
                if (completed == connectTask && tcp.Connected) open.Add(port);
            }
            catch
            {
                // closed
            }
        }

        Console.WriteLine($"Open ports: {string.Join(", ", open)}");
    }

    private static bool TryParseRange(string input, out int start, out int end)
    {
        start = 1; end = 1024;
        var parts = input.Split('-', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 1 && int.TryParse(parts[0], out int single)) { start = single; end = single; return true; }
        if (parts.Length == 2 && int.TryParse(parts[0], out start) && int.TryParse(parts[1], out end)) return true;
        return false;
    }
}

public class ShodanSearchFeature : IFeature
{
    public string Id => "shodan.search";
    public string Name => "Shodan Search";
    public string Description => "Search Shodan (requires API key).";
    public bool IsEnabled { get; set; } = false;

    private static readonly HttpClient _httpLocal = new();

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Shodan API key> ");
        var key = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(key)) { Console.WriteLine("No key provided."); return; }

        Console.Write("Search query> ");
        var q = Console.ReadLine()?.Trim() ?? "";
        if (string.IsNullOrEmpty(q)) { Console.WriteLine("No query."); return; }

        var url = $"https://api.shodan.io/shodan/host/search?key={WebUtility.UrlEncode(key)}&query={WebUtility.UrlEncode(q)}";
        try
        {
            using var res = await _httpLocal.GetAsync(url, cancellationToken);
            if (!res.IsSuccessStatusCode)
            {
                Console.WriteLine($"Shodan returned {(int)res.StatusCode} {res.ReasonPhrase}");
                var txt = await res.Content.ReadAsStringAsync(cancellationToken);
                Console.WriteLine(txt);
                return;
            }

            var content = await res.Content.ReadAsStringAsync(cancellationToken);
            using var doc = JsonDocument.Parse(content);
            if (doc.RootElement.TryGetProperty("matches", out var matches) && matches.ValueKind == JsonValueKind.Array)
            {
                foreach (var m in matches.EnumerateArray().Take(10))
                {
                    var ip = m.GetProperty("ip_str").GetString();
                    var port = m.GetProperty("port").GetInt32();
                    var org = m.TryGetProperty("org", out var orgp) ? orgp.GetString() : "";
                    Console.WriteLine($"{ip}:{port}  {org}");
                }
            }
            else
            {
                Console.WriteLine("No results.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Shodan error: {ex.Message}");
        }
    }
}

public class CertificateTransparencyFeature : IFeature
{
    public string Id => "ct.search";
    public string Name => "Certificate Transparency Search (crt.sh)";
    public string Description => "Queries crt.sh for certificates related to a domain and lists names found.";
    public bool IsEnabled { get; set; } = true;

    private static readonly HttpClient _httpLocal = new();

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Domain> ");
        var domain = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(domain)) { Console.WriteLine("No domain."); return; }

        var url = $"https://crt.sh/?q=%25.{WebUtility.UrlEncode(domain)}&output=json";
        try
        {
            using var res = await _httpLocal.GetAsync(url, cancellationToken);
            if (!res.IsSuccessStatusCode) { Console.WriteLine($"crt.sh returned {(int)res.StatusCode}"); return; }
            var content = await res.Content.ReadAsStringAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(content)) { Console.WriteLine("No results."); return; }

            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var doc = JsonDocument.Parse(content);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    if (item.TryGetProperty("name_value", out var nv))
                    {
                        var raw = nv.GetString() ?? "";
                        foreach (var name in raw.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        {
                            set.Add(name);
                        }
                    }
                }
            }

            Console.WriteLine($"Found {set.Count} distinct names:");
            foreach (var n in set.OrderBy(x => x)) Console.WriteLine(n);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"crt.sh error: {ex.Message}");
        }
    }
}

public class ZoneTransferAttemptFeature : IFeature
{
    public string Id => "dns.axfr";
    public string Name => "Zone Transfer Attempt (enumerate NS)";
    public string Description => "Enumerates authoritative NS records for a domain and attempts to resolve their IPs. Does not perform AXFR.";
    public bool IsEnabled { get; set; } = false;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Domain> ");
        var domain = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(domain)) { Console.WriteLine("No domain."); return; }

        try
        {
            Console.WriteLine("Querying NS records (via DOH)...");
            var doc = await BuiltInFeatureRegistration.DohQueryAsync(domain, "NS", cancellationToken);
            if (doc == null) { Console.WriteLine("Failed to query DOH."); return; }
            if (doc.RootElement.TryGetProperty("Answer", out var answer))
            {
                var ns = new List<string>();
                foreach (var a in answer.EnumerateArray())
                {
                    var data = a.GetProperty("data").GetString() ?? "";
                    ns.Add(data.TrimEnd('.'));
                }
                Console.WriteLine("Authoritative NS:");
                foreach (var n in ns) Console.WriteLine($" - {n}");
                Console.WriteLine("Resolving NS to IPs...");
                foreach (var n in ns)
                {
                    try
                    {
                        var addrs = await Dns.GetHostAddressesAsync(n);
                        Console.WriteLine($"{n} -> {string.Join(", ", addrs.Select(x => x.ToString()))}");
                    }
                    catch { Console.WriteLine($"{n} -> (resolve failed)"); }
                }
            }
            else
            {
                Console.WriteLine("No NS answers returned.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error enumerating nameservers: {ex.Message}");
        }
    }
}

public class PassiveDnsFeature : IFeature
{
    public string Id => "passive.dns";
    public string Name => "Passive DNS / Subdomain via crt.sh";
    public string Description => "Performs a passive lookup via crt.sh to list domains observed in certificates.";
    public bool IsEnabled { get; set; } = true;

    private static readonly HttpClient _httpLocal2 = new();

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Domain> ");
        var domain = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(domain)) { Console.WriteLine("No domain."); return; }

        var url = $"https://crt.sh/?q=%25.{WebUtility.UrlEncode(domain)}&output=json";
        try
        {
            using var res = await _httpLocal2.GetAsync(url, cancellationToken);
            if (!res.IsSuccessStatusCode) { Console.WriteLine($"crt.sh returned {(int)res.StatusCode}"); return; }
            var content = await res.Content.ReadAsStringAsync(cancellationToken);
            if (string.IsNullOrWhiteSpace(content)) { Console.WriteLine("No results."); return; }

            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            using var doc = JsonDocument.Parse(content);
            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    if (item.TryGetProperty("name_value", out var nv))
                    {
                        var raw = nv.GetString() ?? "";
                        foreach (var name in raw.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                        {
                            set.Add(name);
                        }
                    }
                }
            }

            Console.WriteLine($"Passive results ({set.Count}):");
            foreach (var n in set.OrderBy(x => x)) Console.WriteLine(n);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Passive DNS error: {ex.Message}");
        }
    }
}

#endregion

#region Additional usable features (implementations)

public class MxLookupFeature : IFeature
{
    public string Id => "mx.lookup";
    public string Name => "MX Lookup";
    public string Description => "List MX records and resolve mail servers' IPs (DOH)";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Domain> ");
        var domain = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(domain)) { Console.WriteLine("No domain."); return; }

        var doc = await BuiltInFeatureRegistration.DohQueryAsync(domain, "MX", cancellationToken);
        if (doc == null) { Console.WriteLine("DOH query failed."); return; }
        if (!doc.RootElement.TryGetProperty("Answer", out var ans)) { Console.WriteLine("No MX records found."); return; }
        foreach (var a in ans.EnumerateArray())
        {
            var data = a.GetProperty("data").GetString() ?? "";
            Console.WriteLine(data);
            var parts = data.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var host = parts.Length >= 2 ? parts[1].TrimEnd('.') : data;
            try
            {
                var ips = await Dns.GetHostAddressesAsync(host);
                Console.WriteLine($"  -> {string.Join(", ", ips.Select(x => x.ToString()))}");
            }
            catch { Console.WriteLine("  -> (resolve failed)"); }
        }
    }
}

public class TxtLookupFeature : IFeature
{
    public string Id => "txt.lookup";
    public string Name => "TXT / SPF Lookup";
    public string Description => "Fetch TXT records and display SPF records (DOH)";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Domain> ");
        var domain = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(domain)) { Console.WriteLine("No domain."); return; }

        var doc = await BuiltInFeatureRegistration.DohQueryAsync(domain, "TXT", cancellationToken);
        if (doc == null) { Console.WriteLine("DOH query failed."); return; }
        if (!doc.RootElement.TryGetProperty("Answer", out var ans)) { Console.WriteLine("No TXT records found."); return; }
        foreach (var a in ans.EnumerateArray())
        {
            var data = a.GetProperty("data").GetString() ?? "";
            Console.WriteLine(data);
            if (data.Contains("v=spf1", StringComparison.OrdinalIgnoreCase))
                Console.WriteLine("  (SPF record detected)");
        }
    }
}

public class DmarcCheckFeature : IFeature
{
    public string Id => "dmarc.check";
    public string Name => "DMARC Check";
    public string Description => "Retrieve DMARC record and provide basic interpretation";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Domain> ");
        var domain = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(domain)) { Console.WriteLine("No domain."); return; }
        var dmarcName = $"_dmarc.{domain}";
        var doc = await BuiltInFeatureRegistration.DohQueryAsync(dmarcName, "TXT", cancellationToken);
        if (doc == null) { Console.WriteLine("DOH query failed."); return; }
        if (!doc.RootElement.TryGetProperty("Answer", out var ans)) { Console.WriteLine("No DMARC record found."); return; }
        foreach (var a in ans.EnumerateArray())
        {
            var data = a.GetProperty("data").GetString() ?? "";
            Console.WriteLine(data);
        }
    }
}

public class DnssecCheckFeature : IFeature
{
    public string Id => "dnssec.check";
    public string Name => "DNSSEC Check";
    public string Description => "Check whether the domain has DNSSEC records (DOH, presence of RRSIG/DS)";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Domain> ");
        var domain = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(domain)) { Console.WriteLine("No domain."); return; }

        var doc = await BuiltInFeatureRegistration.DohQueryAsync(domain, "RRSIG", cancellationToken);
        if (doc == null) { Console.WriteLine("DOH query failed."); return; }
        if (doc.RootElement.TryGetProperty("Answer", out var ans))
        {
            Console.WriteLine("RRSIG records present -> DNSSEC signatures exist.");
        }
        else
        {
            Console.WriteLine("No RRSIG records found. DNSSEC probably not configured.");
        }
    }
}

public class AsnGeoIpFeature : IFeature
{
    public string Id => "asn.geoip";
    public string Name => "ASN & GeoIP Lookup";
    public string Description => "Resolve ASN and geolocation for an IP using ip-api.com (no key required)";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("IP or Host> ");
        var input = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(input)) { Console.WriteLine("No input."); return; }

        string ip = input;
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(input);
            if (addrs.Length > 0) ip = addrs[0].ToString();
        }
        catch { /* ignore */ }

        var url = $"http://ip-api.com/json/{WebUtility.UrlEncode(ip)}?fields=status,message,country,regionName,city,isp,org,as,query";
        var doc = await BuiltInFeatureRegistration.GetJsonAsync(url, cancellationToken);
        if (doc == null) { Console.WriteLine("Lookup failed."); return; }
        var root = doc.RootElement;
        if (root.GetProperty("status").GetString() != "success")
        {
            Console.WriteLine($"Error: {root.GetProperty("message").GetString()}");
            return;
        }
        Console.WriteLine($"IP: {root.GetProperty("query").GetString()}");
        Console.WriteLine($"ASN/Org: {root.GetProperty("as").GetString()} / {root.GetProperty("org").GetString()}");
        Console.WriteLine($"ISP: {root.GetProperty("isp").GetString()}");
        Console.WriteLine($"Location: {root.GetProperty("city").GetString()}, {root.GetProperty("regionName").GetString()}, {root.GetProperty("country").GetString()}");
    }
}

public class TracerouteFeature : IFeature
{
    public string Id => "traceroute";
    public string Name => "Traceroute (ICMP TTL)";
    public string Description => "Perform a basic traceroute using Ping with increasing TTL.";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Host> ");
        var host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host)) { Console.WriteLine("No host."); return; }

        int maxHops = 30;
        for (int ttl = 1; ttl <= maxHops; ttl++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                using var ping = new Ping();
                var options = new PingOptions(ttl, true);
                var reply = await ping.SendPingAsync(host, 3000, new byte[32], options);
                Console.WriteLine($"{ttl}\t{reply.Status}\t{reply.Address}");
                if (reply.Status == IPStatus.Success) break;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{ttl}\tError: {ex.Message}");
            }
        }
    }
}

public class ReverseIpFeature : IFeature
{
    public string Id => "reverseip";
    public string Name => "Reverse IP / Shared Hostnames";
    public string Description => "Resolve PTR for an IP and optionally brute common hostnames that map to the same IP.";
    public bool IsEnabled { get; set; } = true;

    private static readonly string[] SmallHostnames = new[] { "www", "mail", "api", "dev", "test", "webmail", "ftp", "shop", "blog" };

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("IP or Host> ");
        var input = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(input)) { Console.WriteLine("No input."); return; }

        string ip = input;
        try
        {
            var addrs = await Dns.GetHostAddressesAsync(input);
            if (addrs.Length > 0) ip = addrs[0].ToString();
        }
        catch { /* ignore */ }

        try
        {
            var entry = await Dns.GetHostEntryAsync(ip);
            Console.WriteLine($"PTR: {entry.HostName}");
        }
        catch { Console.WriteLine("No PTR record found."); }

        Console.Write("Try small host permutations on parent domain? (y/N)> ");
        var yn = Console.ReadLine()?.Trim();
        if (!string.Equals(yn, "y", StringComparison.OrdinalIgnoreCase)) return;

        // attempt to detect parent domain (very naive)
        Console.Write("Parent domain (e.g. example.com)> ");
        var domain = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(domain)) return;

        foreach (var h in SmallHostnames)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var host = $"{h}.{domain}";
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(host);
                if (addrs.Any(a => a.ToString() == ip))
                    Console.WriteLine($"{host} -> {ip} (matches)");
            }
            catch { }
        }
    }
}

public class CdnDetectFeature : IFeature
{
    public string Id => "cdn.detect";
    public string Name => "CDN Detection";
    public string Description => "Check common headers and IP ranges to attempt CDN detection.";
    public bool IsEnabled { get; set; } = true;

    private static readonly string[] CdnHeaders = new[] { "Server", "Via", "X-Cache", "CF-Ray", "X-CDN", "X-Akamai-Staging" };

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("URL> ");
        var url = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(url)) return;
        if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase)) url = "http://" + url;

        try
        {
            using var res = await BuiltInFeatureRegistration.GetJsonAsync(url, cancellationToken); // will be null for non-json, handle below
        }
        catch { /* ignore */ }

        try
        {
            using var client = new HttpClient();
            using var res = await client.GetAsync(url, cancellationToken);
            Console.WriteLine($"Status {(int)res.StatusCode}");
            foreach (var h in res.Headers)
            {
                if (CdnHeaders.Contains(h.Key, StringComparer.OrdinalIgnoreCase))
                    Console.WriteLine($"{h.Key}: {string.Join(", ", h.Value)}");
            }
            foreach (var h in res.Content.Headers)
            {
                if (CdnHeaders.Contains(h.Key, StringComparer.OrdinalIgnoreCase))
                    Console.WriteLine($"{h.Key}: {string.Join(", ", h.Value)}");
            }
            Console.WriteLine("Check header hints above for CDN providers (Cloudflare -> CF-Ray, Akamai -> X-CDN/X-Akamai-* etc.)");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error fetching headers: {ex.Message}");
        }
    }
}

public class RobotsFetchFeature : IFeature
{
    public string Id => "robots.fetch";
    public string Name => "robots.txt Fetch";
    public string Description => "Fetch and display robots.txt";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Site host (example.com)> ");
        var host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host)) return;
        var url = host.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? host : $"https://{host}";
        if (!url.EndsWith("/")) url += "/";
        url += "robots.txt";

        try
        {
            using var res = await new HttpClient().GetAsync(url, cancellationToken);
            if (!res.IsSuccessStatusCode) { Console.WriteLine($"robots.txt returned {(int)res.StatusCode}"); return; }
            var content = await res.Content.ReadAsStringAsync(cancellationToken);
            Console.WriteLine(content);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error fetching robots.txt: {ex.Message}");
        }
    }
}

public class SitemapFetchFeature : IFeature
{
    public string Id => "sitemap.fetch";
    public string Name => "sitemap.xml Fetch";
    public string Description => "Fetch sitemap.xml and list URLs (if present)";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Site host (example.com)> ");
        var host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host)) return;
        var url = host.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? host : $"https://{host}";
        if (!url.EndsWith("/")) url += "/";
        url += "sitemap.xml";

        try
        {
            using var res = await new HttpClient().GetAsync(url, cancellationToken);
            if (!res.IsSuccessStatusCode) { Console.WriteLine($"sitemap.xml returned {(int)res.StatusCode}"); return; }
            var content = await res.Content.ReadAsStringAsync(cancellationToken);
            Console.WriteLine(content);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error fetching sitemap.xml: {ex.Message}");
        }
    }
}

public class FaviconHashFeature : IFeature
{
    public string Id => "favicon.hash";
    public string Name => "Favicon Hash";
    public string Description => "Download favicon and compute a SHA256 hash for fingerprinting";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Host (example.com)> ");
        var host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host)) return;
        var url = host.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? host : $"https://{host}";
        if (!url.EndsWith("/")) url += "/";
        url += "favicon.ico";

        try
        {
            using var res = await new HttpClient().GetAsync(url, cancellationToken);
            if (!res.IsSuccessStatusCode) { Console.WriteLine($"favicon returned {(int)res.StatusCode}"); return; }
            var bytes = await res.Content.ReadAsByteArrayAsync(cancellationToken);
            using var sha = SHA256.Create();
            var hash = sha.ComputeHash(bytes);
            Console.WriteLine($"SHA256: {BitConverter.ToString(hash).Replace(\"-\",\"\")}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error fetching favicon: {ex.Message}");
        }
    }
}

public class TlsProbeFeature : IFeature
{
    public string Id => "tls.probe";
    public string Name => "TLS Probe (basic)";
    public string Description => "Fetch TLS protocol version and basic certificate info";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Host> ");
        var host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host)) return;
        try
        {
            using var client = new TcpClient();
            await client.ConnectAsync(host, 443);
            using var ns = client.GetStream();
            var ssl = new System.Net.Security.SslStream(ns, false, (a, b, c, d) => true);
            await ssl.AuthenticateAsClientAsync(host);
            Console.WriteLine($"Protocol: {ssl.SslProtocol}");
            var cert = new X509Certificate2(ssl.RemoteCertificate);
            Console.WriteLine($"Certificate Subject: {cert.Subject}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"TLS probe failed: {ex.Message}");
        }
    }
}

public class HstsCheckFeature : IFeature
{
    public string Id => "hsts.check";
    public string Name => "HSTS Check";
    public string Description => "Check Strict-Transport-Security header presence and max-age";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("URL> ");
        var url = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(url)) return;
        if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase)) url = "https://" + url;

        try
        {
            using var res = await new HttpClient().GetAsync(url, cancellationToken);
            if (res.Headers.TryGetValues("Strict-Transport-Security", out var vals))
            {
                foreach (var v in vals) Console.WriteLine($"HSTS: {v}");
            }
            else
            {
                Console.WriteLine("No HSTS header present.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}

public class OpenRedirectScanFeature : IFeature
{
    public string Id => "openredirect.scan";
    public string Name => "Open Redirect Scanner (basic)";
    public string Description => "Test common redirect parameters for open redirect behavior";
    public bool IsEnabled { get; set; } = true;

    private static readonly string[] CommonParams = new[] { "url", "next", "redirect", "return", "rurl", "dest" };

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("URL (base, e.g. https://example.com/path?param=1)> ");
        var baseUrl = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(baseUrl)) return;
        var testTarget = "https://example.com/";
        foreach (var p in CommonParams)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var uri = baseUrl.Contains("?") ? $"{baseUrl}&{p}={WebUtility.UrlEncode(testTarget)}" : $"{baseUrl}?{p}={WebUtility.UrlEncode(testTarget)}";
            try
            {
                using var http = new HttpClient(new HttpClientHandler() { AllowAutoRedirect = false });
                var res = await http.GetAsync(uri, cancellationToken);
                if ((int)res.StatusCode >= 300 && (int)res.StatusCode < 400 && res.Headers.Location != null)
                {
                    var loc = res.Headers.Location.ToString();
                    Console.WriteLine($"{p} -> redirect to {loc}");
                    if (loc.StartsWith(testTarget)) Console.WriteLine("  Possible open redirect!");
                }
                else
                {
                    Console.WriteLine($"{p} -> no redirect ({(int)res.StatusCode})");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"{p} -> error: {ex.Message}");
            }
        }
    }
}

public class SubdomainPermutationFeature : IFeature
{
    public string Id => "subpermute";
    public string Name => "Subdomain Permutation";
    public string Description => "Generate simple permutations of a subdomain list and attempt resolution";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Base domain> ");
        var domain = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(domain)) return;

        Console.Write("Comma-separated discovered subdomains (or blank to use default [www,api,dev])> ");
        var line = Console.ReadLine();
        var subs = string.IsNullOrWhiteSpace(line) ? new[] { "www", "api", "dev" } : line.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var permutations = new List<string>();
        foreach (var s in subs)
        {
            permutations.Add($"{s}-{domain}");
            permutations.Add($"{s}2.{domain}");
            permutations.Add($"{s}dev.{domain}");
            permutations.Add($"{s}staging.{domain}");
        }

        foreach (var p in permutations)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(p);
                if (addrs.Length > 0) Console.WriteLine($"{p} -> {string.Join(", ", addrs.Select(x => x.ToString()))}");
            }
            catch { }
        }
    }
}

public class CertIssuerSearchFeature : IFeature
{
    public string Id => "cert.issuer.search";
    public string Name => "Certificate Issuer Search (crt.sh)";
    public string Description => "Query crt.sh for certificates filtered by issuer (placeholder)";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Issuer name fragment> ");
        var issuer = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(issuer)) return;

        // crt.sh supports searching by issuer but we will do a simple name query
        var url = $"https://crt.sh/?q={WebUtility.UrlEncode(issuer)}&output=json";
        var doc = await BuiltInFeatureRegistration.GetJsonAsync(url, cancellationToken);
        if (doc == null) { Console.WriteLine("Query failed or no results."); return; }
        Console.WriteLine("Results:");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in doc.RootElement.EnumerateArray().Take(50))
        {
            if (item.TryGetProperty("name_value", out var nv))
            {
                foreach (var n in nv.GetString()!.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    if (seen.Add(n)) Console.WriteLine(n);
                }
            }
        }
    }
}

public class WaybackLookupFeature : IFeature
{
    public string Id => "wayback.lookup";
    public string Name => "Wayback / Archive Lookup";
    public string Description => "List archived URLs from Wayback (web.archive.org)";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Domain or URL> ");
        var target = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(target)) return;

        var url = $"http://web.archive.org/cdx/search/cdx?url={WebUtility.UrlEncode(target)}&output=json&limit=50";
        var doc = await BuiltInFeatureRegistration.GetJsonAsync(url, cancellationToken);
        if (doc == null) { Console.WriteLine("Wayback query failed or no results."); return; }
        foreach (var item in doc.RootElement.EnumerateArray().Skip(1).Take(50))
        {
            // format varies; print best-effort
            try { Console.WriteLine(item[2].GetString()); } catch { Console.WriteLine(item.ToString()); }
        }
    }
}

public class RobotsSitemapAnalyzerFeature : IFeature
{
    public string Id => "robots.sitemap.analyze";
    public string Name => "Robots / Sitemap Analyzer";
    public string Description => "Fetch robots and sitemap and show simple summary";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Site host (example.com)> ");
        var host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host)) return;

        // robots
        try
        {
            var robotsUrl = (host.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? host : "https://" + host).TrimEnd('/') + "/robots.txt";
            using var res = await new HttpClient().GetAsync(robotsUrl, cancellationToken);
            if (res.IsSuccessStatusCode)
            {
                var txt = await res.Content.ReadAsStringAsync(cancellationToken);
                Console.WriteLine("robots.txt:");
                Console.WriteLine(txt.Split('\n').Take(20).Aggregate((a, b) => a + "\n" + b));
            }
            else Console.WriteLine("robots.txt not found.");
        }
        catch { Console.WriteLine("robots fetch failed."); }

        // sitemap discovery via robots (quick)
        try
        {
            var robotsUrl = (host.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? host : "https://" + host).TrimEnd('/') + "/robots.txt";
            using var res = await new HttpClient().GetAsync(robotsUrl, cancellationToken);
            if (res.IsSuccessStatusCode)
            {
                var txt = await res.Content.ReadAsStringAsync(cancellationToken);
                var lines = txt.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                var sitemaps = lines.Where(l => l.StartsWith("Sitemap:", StringComparison.OrdinalIgnoreCase)).Select(l => l.Substring(8).Trim());
                foreach (var s in sitemaps) Console.WriteLine($"Sitemap: {s}");
            }
        }
        catch { /* ignore */ }
    }
}

public class BannerGrabFeature : IFeature
{
    public string Id => "banner.grab";
    public string Name => "Port Banner Grab";
    public string Description => "Attempt to read service banners on open ports";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Host> ");
        var host = Console.ReadLine()?.Trim();
        Console.Write("Port> ");
        var portStr = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host) || !int.TryParse(portStr, out int port)) { Console.WriteLine("Invalid input."); return; }

        try
        {
            using var tcp = new TcpClient();
            var ctask = tcp.ConnectAsync(host, port);
            var completed = await Task.WhenAny(ctask, Task.Delay(2000, cancellationToken));
            if (completed != ctask || !tcp.Connected) { Console.WriteLine("Connect failed/timeout."); return; }

            using var stream = tcp.GetStream();
            stream.ReadTimeout = 2000;
            var buffer = new byte[1024];
            try
            {
                var read = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken);
                Console.WriteLine(Encoding.UTF8.GetString(buffer, 0, Math.Max(0, read)));
            }
            catch (Exception)
            {
                Console.WriteLine("No banner read (service may require input).");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Banner grab error: {ex.Message}");
        }
    }
}

public class HttpMethodsFeature : IFeature
{
    public string Id => "http.methods";
    public string Name => "HTTP Methods Check";
    public string Description => "Check allowed HTTP methods (OPTIONS)";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("URL> ");
        var url = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(url)) return;
        if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase)) url = "http://" + url;

        try
        {
            using var client = new HttpClient();
            var req = new HttpRequestMessage(HttpMethod.Options, url);
            var res = await client.SendAsync(req, cancellationToken);
            if (res.Headers.TryGetValues("Allow", out var allow))
            {
                Console.WriteLine($"Allow: {string.Join(", ", allow)}");
            }
            else
            {
                Console.WriteLine("No Allow header returned. Status: " + (int)res.StatusCode);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}

public class DnsBruteForceFeature : IFeature
{
    public string Id => "dns.bruteforce";
    public string Name => "DNS Brute Force (small)";
    public string Description => "Runs a small DNS brute-force wordlist (local, safe)";
    public bool IsEnabled { get; set; } = true;

    private static readonly string[] SmallWordlist = new[] { "www", "mail", "ftp", "api", "dev", "test", "shop", "blog" };

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Domain> ");
        var domain = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(domain)) return;

        foreach (var w in SmallWordlist)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var host = $"{w}.{domain}";
            try
            {
                var addrs = await Dns.GetHostAddressesAsync(host);
                if (addrs.Length > 0) Console.WriteLine($"{host} -> {string.Join(", ", addrs.Select(x => x.ToString()))}");
            }
            catch { }
        }
    }
}

public class PtrSweepFeature : IFeature
{
    public string Id => "ptr.sweep";
    public string Name => "PTR Sweep";
    public string Description => "Reverse-sweep a small IP range for PTR records (placeholder)";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("CIDR (e.g. 192.0.2.0/30)> ");
        var cidr = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(cidr)) return;

        Console.WriteLine("This is a placeholder; for safety only small ranges are allowed.");
        // naive parse for /30 or /29
        var parts = cidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var baseIp) || !int.TryParse(parts[1], out int prefix)) { Console.WriteLine("Invalid CIDR."); return; }
        if (prefix < 24) { Console.WriteLine("Refusing large ranges in this placeholder."); return; }

        // generate a few IPs (simple)
        var ipBytes = baseIp.GetAddressBytes();
        for (int i = 0; i < 4; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var ip = new IPAddress(ipBytes);
                var rev = await Dns.GetHostEntryAsync(ip);
                Console.WriteLine($"{ip} -> {rev.HostName}");
                ipBytes[ipBytes.Length - 1]++;
            }
            catch { ipBytes[ipBytes.Length - 1]++; }
        }
    }
}

public class TakeoverCheckFeature : IFeature
{
    public string Id => "takeover.check";
    public string Name => "Subdomain Takeover Check (basic)";
    public string Description => "Check for common takeover signatures on 404 / known provider responses";
    public bool IsEnabled { get; set; } = true;

    private static readonly string[] Signatures = new[] { "NoSuchBucket", "There isn't a GitHub Pages site here", "No such app" };

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("Host (subdomain) to check> ");
        var host = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(host)) return;
        var url = host.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? host : "http://" + host;
        try
        {
            var res = await new HttpClient().GetAsync(url, cancellationToken);
            var body = await res.Content.ReadAsStringAsync(cancellationToken);
            foreach (var s in Signatures)
            {
                if (body.Contains(s, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"Possible takeover signature found: {s}");
                }
            }
            Console.WriteLine("Done (basic check).");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}

public class EmailHarvesterFeature : IFeature
{
    public string Id => "email.harvester";
    public string Name => "Email Harvester (basic)";
    public string Description => "Fetch a page and extract emails (simple regex)";
    public bool IsEnabled { get; set; } = true;

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Console.Write("URL to harvest > ");
        var url = Console.ReadLine()?.Trim();
        if (string.IsNullOrEmpty(url)) return;
        if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase)) url = "http://" + url;
        try
        {
            var s = await new HttpClient().GetStringAsync(url);
            var emails = System.Text.RegularExpressions.Regex.Matches(s, @"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}");
            var set = new HashSet<string>();
            foreach (System.Text.RegularExpressions.Match m in emails) set.Add(m.Value);
            foreach (var e in set) Console.WriteLine(e);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
        }
    }
}

public class BlacklistCheckPlaceholder : IFeature
{
    public string Id => "blacklist.check";
    public string Name => "Blacklist Check (placeholder)";
    public string Description => "Basic guidance to check public blacklists (no direct checks) - provide APIs to integrate.";
    public bool IsEnabled { get; set; } = false;

    public Task RunAsync(CancellationToken cancellationToken)
    {
        Console.WriteLine("This feature is a placeholder. To perform blacklist checks integrate APIs (Spamhaus, AbuseIPDB, etc.) and provide API keys.");
        return Task.CompletedTask;
    }
}

public class ScreenshotPlaceholder : IFeature
{
    public string Id => "screenshot";
    public string Name => "Screenshot Capture (placeholder)";
    public string Description => "Placeholder: integrate a screenshot service or headless browser to capture pages.";
    public bool IsEnabled { get; set; } = false;

    public Task RunAsync(CancellationToken cancellationToken)
    {
        Console.WriteLine("Screenshot capture not implemented. Consider using an external service or Puppeteer/Playwright integration.");
        return Task.CompletedTask;
    }
}

public class MetadataExtractPlaceholder : IFeature
{
    public string Id => "metadata.extract";
    public string Name => "Metadata / EXIF Extraction (placeholder)";
    public string Description => "Download a file and attempt to extract EXIF/metadata (requires library integration).";
    public bool IsEnabled { get; set; } = false;

    public Task RunAsync(CancellationToken cancellationToken)
    {
        Console.WriteLine("Metadata extraction not implemented. Integrate a library for EXIF/office metadata to enable this feature.");
        return Task.CompletedTask;
    }
}

public class ImageReversePlaceholder : IFeature
{
    public string Id => "image.reverse";
    public string Name => "Reverse Image / Logo Search (placeholder)";
    public string Description => "Placeholder: integrate with Google/Tineye/APIs to perform reverse image searches.";
    public bool IsEnabled { get; set; } = false;

    public Task RunAsync(CancellationToken cancellationToken)
    {
        Console.WriteLine("Reverse image search not implemented. Provide API key / integration to enable this.");
        return Task.CompletedTask;
    }
}

#endregion

#region Placeholders left intentionally lightweight

public class PlaceholderFeature : IFeature
{
    public string Id { get; }
    public string Name { get; }
    public string Description { get; }
    public bool IsEnabled { get; set; } = false;

    public PlaceholderFeature(string id, string name, string desc)
    {
        Id = id;
        Name = name;
        Description = desc;
    }

    public Task RunAsync(CancellationToken cancellationToken)
    {
        Console.WriteLine($"{Name} ({Id}) is a placeholder. Implement functionality in code.");
        return Task.CompletedTask;
    }
}

public class WhoisPlaceholderFeature : IFeature
{
    public string Id => "whois";
    public string Name => "WHOIS (placeholder)";
    public string Description => "Placeholder for WHOIS lookups. Replace with real WHOIS logic or an API integration.";
    public bool IsEnabled { get; set; } = false;

    public Task RunAsync(CancellationToken cancellationToken)
    {
        Console.WriteLine("WHOIS is not implemented in this scaffold. Consider using a whois library or an HTTP WHOIS API.");
        return Task.CompletedTask;
    }
}

#endregion