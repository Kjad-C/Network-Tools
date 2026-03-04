using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

public class FeatureManager
{
    private readonly List<IFeature> _features = new();

    // Menu pagination settings
    public int PageSize { get; set; } = 10;

    public void Register(IFeature f) => _features.Add(f);

    public IReadOnlyList<IFeature> Features => _features;

    public void GeneratePlaceholderFeatures(int upTo)
    {
        int start = _features.Count + 1;
        for (int i = start; i <= upTo; i++)
        {
            Register(new PlaceholderFeature($"placeholder.{i}", $"Placeholder {i}", "Auto-generated placeholder feature"));
        }
    }

    public async Task RunMainMenuAsync(CancellationToken token)
    {
        int page = 0;
        var filtered = _features.ToList();

        while (!token.IsCancellationRequested)
        {
            Console.Clear();
            Console.WriteLine("=== Network OSINT — Main Menu ===");
            Console.WriteLine($"Features: {filtered.Count}  (Page {page + 1}/{Math.Max(1, (int)Math.Ceiling(filtered.Count / (double)PageSize))})");
            Console.WriteLine();

            var pageItems = filtered.Skip(page * PageSize).Take(PageSize).ToList();
            for (int i = 0; i < pageItems.Count; i++)
            {
                var f = pageItems[i];
                Console.WriteLine($"{i + 1}. {f.Name} {(f.IsEnabled ? "" : "(disabled)")}");
                Console.WriteLine($"    {f.Description}");
            }

            Console.WriteLine();
            Console.WriteLine("Commands: [number] Run | s Search | n Next | p Prev | e Enable/Disable | q Quit | h Help");
            Console.Write("Input> ");
            var input = Console.ReadLine()?.Trim() ?? "";

            if (string.IsNullOrEmpty(input)) continue;
            if (input.Equals("q", StringComparison.OrdinalIgnoreCase)) break;
            if (input.Equals("n", StringComparison.OrdinalIgnoreCase)) { page++; if (page * PageSize >= filtered.Count) page = 0; continue; }
            if (input.Equals("p", StringComparison.OrdinalIgnoreCase)) { page--; if (page < 0) page = Math.Max(0, (int)Math.Ceiling(filtered.Count / (double)PageSize) - 1); continue; }
            if (input.Equals("h", StringComparison.OrdinalIgnoreCase)) { ShowHelp(); continue; }

            if (input.StartsWith("s ", StringComparison.OrdinalIgnoreCase) || input.Equals("s", StringComparison.OrdinalIgnoreCase))
            {
                Console.Write("Search term (empty to reset)> ");
                var term = Console.ReadLine() ?? "";
                if (string.IsNullOrWhiteSpace(term)) filtered = _features.ToList();
                else filtered = _features.Where(x => x.Name.Contains(term, StringComparison.OrdinalIgnoreCase) || x.Description.Contains(term, StringComparison.OrdinalIgnoreCase)).ToList();
                page = 0;
                continue;
            }

            if (input.StartsWith("e ", StringComparison.OrdinalIgnoreCase) || input.Equals("e", StringComparison.OrdinalIgnoreCase))
            {
                Console.Write("Enter feature number on current page to toggle> ");
                var idInput = Console.ReadLine();
                if (int.TryParse(idInput, out int idx) && idx >= 1 && idx <= pageItems.Count)
                {
                    var f = pageItems[idx - 1];
                    f.IsEnabled = !f.IsEnabled;
                    Console.WriteLine($"{f.Name} is now {(f.IsEnabled ? "enabled" : "disabled")}.");
                }
                else Console.WriteLine("Invalid selection.");
                Console.WriteLine("Press Enter to continue...");
                Console.ReadLine();
                continue;
            }

            // Run by number on current page
            if (int.TryParse(input, out int selection) && selection >= 1 && selection <= pageItems.Count)
            {
                var feature = pageItems[selection - 1];
                if (!feature.IsEnabled)
                {
                    Console.WriteLine("Feature is disabled. Enable it first with 'e'. Press Enter to continue...");
                    Console.ReadLine();
                    continue;
                }

                Console.WriteLine($"--- Running: {feature.Name} ---");
                try
                {
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(token);
                    // Allow the feature to be cancellable by pressing enter
                    var runTask = feature.RunAsync(cts.Token);
                    Console.WriteLine("Press Enter to cancel the operation (if supported)...");
                    var cancelTask = Task.Run(() => Console.ReadLine());
                    var completed = await Task.WhenAny(runTask, cancelTask);
                    if (completed == cancelTask) cts.Cancel();
                    await runTask;
                }
                catch (OperationCanceledException)
                {
                    Console.WriteLine("Operation canceled.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Feature threw an error: {ex.Message}");
                }

                Console.WriteLine("Press Enter to return to menu...");
                Console.ReadLine();
                continue;
            }

            Console.WriteLine("Unknown command. Press Enter to continue...");
            Console.ReadLine();
        }
    }

    private static void ShowHelp()
    {
        Console.Clear();
        Console.WriteLine("Help - Main Menu");
        Console.WriteLine(" - Enter the number shown to run a feature on the current page.");
        Console.WriteLine(" - s : search features by name/description.");
        Console.WriteLine(" - n / p : next / previous page.");
        Console.WriteLine(" - e : toggle enable/disable for a feature on the current page.");
        Console.WriteLine(" - q : quit the application.");
        Console.WriteLine();
        Console.WriteLine("Press Enter to return...");
        Console.ReadLine();
    }
}