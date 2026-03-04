using System.Threading;
using System.Threading.Tasks;

public interface IFeature
{
    string Id { get; }
    string Name { get; }
    string Description { get; }
    bool IsEnabled { get; set; }

    /// <summary>
    /// Execute the feature. Use the provided CancellationToken for cooperative cancellation.
    /// </summary>
    Task RunAsync(CancellationToken cancellationToken);
}