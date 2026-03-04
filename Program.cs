using System;
using System.Text;
using System.Threading;

Console.OutputEncoding = Encoding.UTF8;
Console.Title = "Network OSINT";

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (sender, e) =>
{
    e.Cancel = true;
    cts.Cancel();
    // give user feedback
    var prev = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("\nCancellation requested — returning to menu (or exiting)...");
    Console.ForegroundColor = prev;
};

var manager = new FeatureManager();

// Register built-in features (delegates to BuiltInFeatureRegistration)
try
{
    FeatureRegistration.RegisterDefaults(manager);
}
catch (Exception ex)
{
    var prev = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"Feature registration failed: {ex.Message}");
    Console.ForegroundColor = prev;
    return;
}

// Optionally generate placeholder features up to a target count
manager.GeneratePlaceholderFeatures(upTo: 50);

// Run interactive menu (cancellable via Ctrl+C)
try
{
    await manager.RunMainMenuAsync(cts.Token);
}
catch (OperationCanceledException)
{
    // graceful exit
}
catch (Exception ex)
{
    var prev = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"Unhandled error: {ex}");
    Console.ForegroundColor = prev;
}

Console.WriteLine("Goodbye.");
